//go:build linux

package warden

import (
	"fmt"
	"os"
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
}

// NewPrompter returns the prompt for this desktop: a notification with action buttons.
func NewPrompter() (Prompter, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, fmt.Errorf("warden: no desktop session bus: %w", err)
	}
	n := &dbusNotifier{conn: conn, obj: conn.Object(notifDest, notifPath), ev: make(chan notifyEvent, 16)}
	if err := conn.AddMatchSignal(
		dbus.WithMatchObjectPath(notifPath), dbus.WithMatchInterface(notifIface),
	); err != nil {
		return nil, err
	}
	sig := make(chan *dbus.Signal, 16)
	conn.Signal(sig)
	go func() {
		for s := range sig {
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
