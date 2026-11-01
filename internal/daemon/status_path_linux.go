package daemon

func defaultStatusPath() string { return "/run/manar-edge/status.json" }

// StatusPathFor is where `manar-edge status` reads (the same path).
func StatusPathFor() string { return defaultStatusPath() }
