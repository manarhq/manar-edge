//go:build windows

package watch

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"

	"github.com/manarhq/manar-edge/internal/secrets/host"
)

func cleanupPlatform(ctx context.Context) error {
	return RestoreAudit(execRunner(ctx), systemPolicy{}, stateFile())
}

// secretFiles lists existing secret files in the target directories plus discovered .env files.
func secretFiles() []string {
	var files []string
	for _, h := range host.Homes() {
		for _, t := range Targets(h) {
			ents, _ := os.ReadDir(t.Path)
			for _, e := range ents {
				if p := filepath.Join(t.Path, e.Name()); !e.IsDir() && ClassOf(p) != "" {
					files = append(files, p)
				}
			}
		}
		files = append(files, DiscoverEnv(h, 5, 500)...)
	}
	return files
}

// runPlatform sets the audit rules, then reads event 4663 every few seconds. Alert only.
//
// ponytail: wevtutil polling every 3 s; switch to EvtSubscribe if event latency matters.
func runPlatform(ctx context.Context, out chan<- Event, _ Mode, _ *Gate, _ bool) bool {
	run := execRunner(ctx)
	if _, err := EnableAudit(run, systemPolicy{}, stateFile(), secretFiles()); err != nil {
		log.Printf("manar-edge: secrets watcher unavailable: %v", err)
		notice(out, TypeUnavailable)
		<-ctx.Done()
		return false
	}
	eng := &Engine{Procs: winProcs{}, Out: out, Homes: host.Homes}
	notice(out, TypeAvailable)
	since := time.Now().UTC()
	rescan := time.NewTicker(24 * time.Hour)
	poll := time.NewTicker(3 * time.Second)
	defer rescan.Stop()
	defer poll.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-rescan.C:
			_, _ = EnableAudit(run, systemPolicy{}, stateFile(), secretFiles())
		case <-poll.C:
			raw, err := run("wevtutil", query4663Args(since)...)
			if err != nil {
				notice(out, TypeUnavailable)
				continue
			}
			evs, err := parse4663(string(raw))
			if err != nil {
				continue
			}
			for _, e := range evs {
				if e.At.After(since) {
					since = e.At
				}
				eng.Observe(Proc{PID: e.PID, Exe: e.ProcessName}, e.ObjectName)
			}
		}
	}
}

// winProcs reads the parent chain from a toolhelp snapshot and image names from the process.
type winProcs struct{}

func (winProcs) Get(pid int) (Proc, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return Proc{}, err
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafeSizeof(e))
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if int(e.ProcessID) == pid {
			p := Proc{PID: pid, PPID: int(e.ParentProcessID), Comm: windows.UTF16ToString(e.ExeFile[:])}
			if h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid)); err == nil {
				buf := make([]uint16, 1024)
				n := uint32(len(buf))
				if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil {
					p.Exe = windows.UTF16ToString(buf[:n])
				}
				windows.CloseHandle(h)
			}
			return p, nil
		}
	}
	return Proc{}, os.ErrNotExist
}
