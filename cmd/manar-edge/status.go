package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/manarhq/manar-edge/internal/daemon"
	"github.com/manarhq/manar-edge/internal/hostclient"
	"github.com/manarhq/manar-edge/internal/ports"
)

// `manar-edge status` tells a person whether this computer is protected and, for each problem,
// one line that fixes it. It reads the service's public status file, asks the service manager and
// the local DOOR port, and uses root-only host files only to add detail. It needs no root.

const staleAfter = 5 * time.Minute

// componentOrder is the order of the product parts in the output.
var componentOrder = []struct{ key, label string }{
	{"door", "DOOR (AI traffic check)"},
	{"jail", "JAIL (network limits)"},
	{"warden", "WARDEN (approval prompts)"},
	{"secrets", "Secrets watcher"},
}

type problem struct {
	What string `json:"what"`
	Fix  string `json:"fix"`
}

type statusReport struct {
	OK        bool                        `json:"ok"`
	Device    map[string]string           `json:"device"`
	Service   string                      `json:"service"`
	Enrolment map[string]string           `json:"enrolment"`
	LastSync  *time.Time                  `json:"lastSync,omitempty"`
	Tools     []daemon.ToolStatus         `json:"tools"`
	Parts     map[string]daemon.Component `json:"parts"`
	Problems  []problem                   `json:"problems"`
}

// statusProbes are the things status looks at, replaceable in tests.
type statusProbes struct {
	now        func() time.Time
	service    func() string
	snapshot   func() (*daemon.Snapshot, error)
	hostInfo   func() (*hostclient.Info, error)
	doorUp     func() bool
	hostname   string
	goos, ver  string
	statusPath string
}

func realProbes(base string) statusProbes {
	h, _ := os.Hostname()
	return statusProbes{
		now: time.Now, service: serviceState, hostname: h, goos: runtime.GOOS, ver: version,
		statusPath: daemon.StatusPathFor(),
		snapshot:   func() (*daemon.Snapshot, error) { return daemon.ReadStatus(daemon.StatusPathFor()) },
		hostInfo:   func() (*hostclient.Info, error) { return readHostInfo(base) },
		doorUp: func() bool {
			c := &http.Client{Timeout: time.Second}
			res, err := c.Get(ports.DoorURL + "/healthz")
			if err != nil {
				return false
			}
			res.Body.Close()
			return res.StatusCode == 200
		},
	}
}

func readHostInfo(base string) (*hostclient.Info, error) {
	b, err := os.ReadFile(filepath.Join(hostclient.Dir(base), "host.json"))
	if err != nil {
		return nil, err
	}
	var i hostclient.Info
	return &i, json.Unmarshal(b, &i)
}

func buildStatus(p statusProbes) statusReport {
	r := statusReport{Device: map[string]string{"hostname": p.hostname, "os": p.goos, "manarEdge": p.ver},
		Enrolment: map[string]string{}, Parts: map[string]daemon.Component{}, Tools: []daemon.ToolStatus{}, Problems: []problem{}}
	add := func(what, fix string) { r.Problems = append(r.Problems, problem{what, fix}) }

	snap, serr := p.snapshot()
	info, ierr := p.hostInfo()
	r.Service = p.service()
	switch {
	case ierr == nil && info != nil && info.HostID != "":
		r.Enrolment["state"], r.Enrolment["hostId"], r.Enrolment["tenant"] = "enrolled", info.HostID, info.TenantSlug
	case snap != nil && snap.HostID != "":
		r.Enrolment["state"], r.Enrolment["hostId"], r.Enrolment["tenant"] = "enrolled", snap.HostID, snap.TenantSlug
	case errors.Is(ierr, os.ErrPermission):
		r.Enrolment["state"] = "unknown"
		r.Enrolment["detail"] = "the host files are readable by administrators only"
	case errors.Is(ierr, os.ErrNotExist) && r.Service != "active":
		r.Enrolment["state"] = "not enrolled"
		add("This computer is not connected to Manar.", "Open the console, choose Add device, and run the install command it shows.")
	default:
		r.Enrolment["state"] = "unknown"
	}
	if snap != nil && snap.Status != "" {
		r.Enrolment["approval"] = snap.Status
		switch snap.Status {
		case "PENDING":
			add("This computer is waiting for approval.", "Approve it in the console (Devices).")
		case "REJECTED", "REVOKED":
			add("This computer was "+strings.ToLower(snap.Status)+" in the console.", "Remove Manar ("+fixUninstall+") and install again with a new code if you want it back.")
		}
	}
	if r.Enrolment["state"] == "not enrolled" {
		r.OK = false
		return r
	}

	switch r.Service {
	case "active":
	case "failed":
		add("The Manar service crashed.", fixServiceLog+" shows why; then "+fixRestartService)
	case "inactive":
		add("The Manar service is not running.", fixStartService)
	default:
		if snap == nil || p.now().Sub(snap.UpdatedAt) > staleAfter {
			add("Cannot tell whether the Manar service is running.", fixStartService+" (if it is not)")
		}
	}

	if snap != nil {
		r.LastSync, r.Tools = snap.LastSyncAt, append(r.Tools, snap.Tools...)
		for k, c := range snap.Components {
			r.Parts[k] = c
		}
		fresh := p.now().Sub(snap.UpdatedAt) <= staleAfter
		switch {
		case !fresh && r.Service == "active":
			add("The service is running but has not updated its status for "+humanAge(p.now().Sub(snap.UpdatedAt))+".", fixRestartService)
		case snap.LastError != "":
			add("The last check-in with Manar failed: "+snap.LastError, "Check this computer's internet access; if it works, "+fixServiceLog)
		case snap.LastSyncAt != nil && p.now().Sub(*snap.LastSyncAt) > staleAfter && fresh:
			add("The last successful check-in with Manar was "+humanAge(p.now().Sub(*snap.LastSyncAt))+" ago.", "Check this computer's internet access, then "+fixRestartService)
		}
		if snap.Status == "APPROVED" {
			for _, t := range snap.Tools {
				if !t.Protected {
					add(t.Name+" is not protected.", "Turn protection on for it in the console (AI tools), or see what is in the way: manar-edge protect list")
				}
			}
		}
	} else if serr != nil && r.Service == "active" {
		add("The service is running but has published no status.", "Update Manar to the latest version, then "+fixRestartService)
	}

	for _, c := range componentOrder {
		part, ok := r.Parts[c.key]
		switch {
		case ok && part.State == "problem":
			fix := part.Fix
			if fix == "" {
				fix = fixRestartService + "; if it keeps happening: " + fixServiceLog
			}
			add(c.label+": "+orDefault(part.Detail, "not working"), fix)
		case !ok && c.key == "door":
			if r.Service == "active" && p.doorUp() {
				r.Parts[c.key] = daemon.Component{State: "ok", Detail: "answering on " + ports.DoorListen}
			} else {
				r.Parts[c.key] = daemon.Component{State: "off", Detail: "not answering on " + ports.DoorListen}
			}
		}
	}
	r.OK = len(r.Problems) == 0
	return r
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func humanAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

func printStatusReport(r statusReport, p statusProbes, out io.Writer) {
	fmt.Fprintf(out, "Device       %s (%s), manar-edge %s\n", r.Device["hostname"], r.Device["os"], r.Device["manarEdge"])
	enrol := r.Enrolment["state"]
	if r.Enrolment["tenant"] != "" {
		enrol += ", workspace " + r.Enrolment["tenant"]
	}
	if a := r.Enrolment["approval"]; a != "" {
		enrol += ", " + strings.ToLower(a)
	}
	if d := r.Enrolment["detail"]; d != "" {
		enrol += " (" + d + ")"
	}
	fmt.Fprintf(out, "Enrolment    %s\n", enrol)
	fmt.Fprintf(out, "Service      %s\n", r.Service)
	if r.LastSync != nil {
		fmt.Fprintf(out, "Last sync    %s ago\n", humanAge(p.now().Sub(*r.LastSync)))
	} else if r.Enrolment["state"] != "not enrolled" {
		fmt.Fprintln(out, "Last sync    never")
	}
	if len(r.Tools) == 0 {
		fmt.Fprintln(out, "AI tools     none found yet")
	}
	for i, t := range r.Tools {
		label := "AI tools"
		if i > 0 {
			label = ""
		}
		state := "not protected"
		if t.Protected {
			state = "protected (" + t.Mode + ")"
		}
		fmt.Fprintf(out, "%-12s %s: %s\n", label, t.Name, state)
	}
	for _, c := range componentOrder {
		part, ok := r.Parts[c.key]
		if !ok {
			fmt.Fprintf(out, "%-12s not reported by this version\n", strings.SplitN(c.label, " ", 2)[0])
			continue
		}
		fmt.Fprintf(out, "%-12s %s%s\n", strings.SplitN(c.label, " ", 2)[0], part.State, detailSuffix(part.Detail))
	}
	if r.OK {
		fmt.Fprintln(out, "\nAll good.")
		return
	}
	fmt.Fprintf(out, "\n%d thing(s) to fix:\n", len(r.Problems))
	for _, pr := range r.Problems {
		fmt.Fprintf(out, "  - %s\n    Fix: %s\n", pr.What, pr.Fix)
	}
}

func detailSuffix(d string) string {
	if d == "" {
		return ""
	}
	return " (" + d + ")"
}

// routeStatus is `manar-edge status [--json] [<agent>]`: with an agent it is the jail status of
// that agent (enterprise gateway agents); without, the status of this device. It returns how many
// problems it found, so main can exit 1.
func routeStatus(base string, args []string, out io.Writer) (int, error) {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	var agent string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		agent, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return 0, err
	}
	if agent == "" && fs.NArg() == 1 {
		agent = fs.Arg(0)
	} else if fs.NArg() > 0 {
		return 0, errors.New("usage: manar-edge status [--json] [<agent>]")
	}
	if agent != "" {
		return 0, cmdStatus(base, []string{agent})
	}
	p := realProbes(base)
	r := buildStatus(p)
	if *asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			return 0, err
		}
	} else {
		printStatusReport(r, p, out)
	}
	return len(r.Problems), nil
}
