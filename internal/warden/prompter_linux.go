//go:build linux

package warden

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	notifDest  = "org.freedesktop.Notifications"
	notifPath  = "/org/freedesktop/Notifications"
	notifIface = "org.freedesktop.Notifications"
)

// dbusNotifier talks to the desktop's notification service on the user's session bus.
type dbusNotifier struct {
	conn *dbus.Conn
	obj  dbus.BusObject
	ev   chan notifyEvent

	mu    sync.Mutex
	owner string // unique bus name of the notification service
}

// NewPrompter returns the prompt for this desktop: a notification with action buttons.
func NewPrompter() (Prompter, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, fmt.Errorf("warden: no desktop session bus: %w", err)
	}
	n := &dbusNotifier{conn: conn, obj: conn.Object(notifDest, notifPath), ev: make(chan notifyEvent, 16)}
	if err := conn.AddMatchSignal(
		dbus.WithMatchSender(notifDest),
		dbus.WithMatchObjectPath(notifPath), dbus.WithMatchInterface(notifIface),
	); err != nil {
		return nil, err
	}
	sig := make(chan *dbus.Signal, 16)
	conn.Signal(sig)
	go func() {
		for s := range sig {
			// Any program on the session bus can emit a signal with these names. Only the
			// current owner of the notification service's name is believed (the match rule above
			// is a filter for efficiency; this is the check).
			if !n.fromNotificationService(s.Sender) {
				continue
			}
			switch s.Name {
			case notifIface + ".ActionInvoked":
				if len(s.Body) == 2 {
					id, _ := s.Body[0].(uint32)
					key, _ := s.Body[1].(string)
					n.ev <- notifyEvent{ID: id, Action: key}
				}
			case notifIface + ".NotificationClosed":
				if len(s.Body) >= 1 {
					id, _ := s.Body[0].(uint32)
					n.ev <- notifyEvent{ID: id, Closed: true}
				}
			}
		}
	}()
	return &notifyPrompter{n: n, timeout: 10 * time.Minute}, nil
}

// fromNotificationService reports whether sender is the unique bus name that owns
// org.freedesktop.Notifications now. The owner is looked up again when it differs, because the
// service can restart under a new unique name.
func (n *dbusNotifier) fromNotificationService(sender string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if sender != "" && sender == n.owner {
		return true
	}
	var owner string
	if err := n.conn.BusObject().Call("org.freedesktop.DBus.GetNameOwner", 0, notifDest).Store(&owner); err != nil {
		return false
	}
	n.owner = owner
	return sender != "" && sender == owner
}

func (n *dbusNotifier) Notify(summary, body string, actions []string, urgent bool) (uint32, error) {
	if actions == nil {
		actions = []string{}
	}
	hints := map[string]dbus.Variant{
		"urgency":        dbus.MakeVariant(byte(2)), // critical: stays until answered
		"suppress-sound": dbus.MakeVariant(true),    // off by default (decision #59)
		"desktop-entry":  dbus.MakeVariant("manar-warden"),
	}
	var id uint32
	call := n.obj.Call(notifIface+".Notify", 0, "WARDEN", uint32(0), "", summary, body, actions, hints, int32(0))
	if call.Err != nil {
		return 0, call.Err
	}
	if err := call.Store(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func (n *dbusNotifier) Close(id uint32) error {
	return n.obj.Call(notifIface+".CloseNotification", 0, id).Err
}

func (n *dbusNotifier) Events() <-chan notifyEvent { return n.ev }

// Lang picks the prompt language from the user's locale variables.
func SystemLang() Lang {
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"} {
		if v := os.Getenv(k); v != "" {
			return LangFromLocale(v)
		}
	}
	return EN
}
