# Secret blocking on Linux (default on)

The device service watches secret files with fanotify and can refuse an **AI tool's own** open of
them. The setting comes from `GET /host/v1/config` `features`:

| Feature | Mode | What happens |
|---|---|---|
| none | alert | opens are reported, never refused |
| `secrets.block` | keys (default for new workspaces) | ssh keys, AWS / Azure / Google Cloud credentials, npm, PyPI and GitHub tokens are refused for an AI tool until the person allows that program. `.env` files, kube and docker config and browser stores are reported only |
| `secrets.block` + `secrets.block.all` | all | every watched class is treated like keys |

Only a catalogue tool that is on the blockable list (its desktop app or stand-alone CLI) with no
interactive shell between it and the opener is refused. The person's own shell, ssh, git, the aws CLI
and editor terminals are never refused. Every doubt (unknown process, unreadable /proc, any error)
allows.

## Ask once per program

The first refused open starts one question (`kind: file`, `ref: <class>`) through the Approver; the
tool gets "permission denied" at once and its next try passes after the person answered. Allow once
is a 60 second window; 8 hours and Always are kept in `<state>/secrets/file-grants.json` (0600). No
answer in 2 minutes is a denial, logged as `secret.vault.denied`; the same question is not asked
again for 5 minutes.

A grant belongs to (user, tool, file class, executable path, SHA-256 of the executable). The hash comes
from the opening process's own `/proc/<pid>/exe` link and is cached by device, inode, size and mtime;
it is computed in the background, so the first open of a program is always refused. A program that
cannot be hashed or pinned is refused and never gets a standing grant. A file owned by a different
user than the opener never uses a grant and nobody is asked about it.

Files are watched through their parent directory, so a token file replaced by write-and-rename stays
protected at once. Ceilings: a directory that did not exist at start (first `gh auth login`) is
picked up within 30 seconds; new `.env` files within the hour. Opens of other files directly in
`$HOME` pass through the watcher and are answered at once.

## If you cannot read your own key

1. The kernel only holds an open while the **service process** is alive and not answering. Stopping or
   killing it releases every waiting open and drops all marks:
   `sudo systemctl stop manar-edge` (or `sudo kill -9 $(pidof manar-edge)`; systemd restarts it and
   it comes back with the same setting, so stop it if you want it to stay down).
2. A stalled watcher turns itself off after 2 seconds and the device shows `monitoring unavailable`.
3. Turn blocking off for the workspace in the console (Secrets, Alert only); the device follows
   within 5 minutes.
4. `sudo manar-edge uninstall` removes the service, the remembered answers and restores any vaulted
   secret first.

Tested on a real kernel: `sudo go test -tags fanotify_integration -run Fanotify ./internal/secrets/watch`
(including "holder killed, a waiting open goes through").

## ssh vault

`secrets.vault.ssh` stays off on Linux. Moving a key out of `~/.ssh` into an agent needs a per-user
agent that Manar keeps loaded across logins, with confirm-on-use; that is not built, and a lost agent
would lock the person out of their own key. Linux keys are protected by the block above instead.
