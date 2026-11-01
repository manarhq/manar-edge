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

## ssh vault (opt-in per key, feature `secrets.vault.ssh`, offered by default)

Nothing moves on its own. The person clicks "Move to vault" next to a detected key in the console
(Secrets page), or runs `manar-edge vault add ~/.ssh/<key>` as themselves. A key with a passphrase is
never moved (it is already protected).

What happens, in this order, and any failure before the last step leaves the key file where it is:
1. The service reads the key as the owner (`O_NOFOLLOW`, no links), writes it to the vault, and reads
   it back byte for byte. Vault files are AES-256-GCM encrypted with `<state>/vault.key` (0600, root),
   so the vault folder alone, or a copy of it, holds nothing readable. The encrypted original is the
   backup used by restore.
2. The key is loaded into Manar's per-user agent, listening on `/run/manar-edge/ssh-<uid>.sock`
   (0600, owner only, peer checked with SO_PEERCRED).
3. A marked block is added to the user's `~/.profile`, `~/.bash_profile`, `~/.bashrc`, `~/.zshenv`
   (those that exist; the original of each is kept in the vault) and to fish's `conf.d`. It sets
   `SSH_AUTH_SOCK` to the Manar socket only while that socket exists, and remembers the previous
   agent in `MANAR_UPSTREAM_SSH_AUTH_SOCK`; Manar's agent passes the user's other keys, `ssh-add` and
   signing for them through to that agent, so no other key is lost.
4. Only then the key file is removed. Open a new terminal (or log in again) to pick up the snippet.

Who may sign: a sign request from the person's own program (no AI tool above it, or an interactive
terminal between it and the tool: you typing `ssh` or `git push`) is answered at once. A request from
an AI tool's non-interactive chain is a question to the person (WARDEN): once, 8 hours or always for
that exact binary (SHA-256) and user. No answer in 2 minutes is a denial. Honest ceiling: this is a
policy for honest tools; a program running as you that is not in the catalogue can still ask the
agent to sign (it cannot read the key).

Put it back (needs no API and no internet):
- `manar-edge vault restore <key>` or `manar-edge vault restore --all` (as yourself through the
  service, or with sudo straight from the vault folder when the service is down). The file returns
  byte for byte with its original mode, the profile files return to their original bytes, the socket
  goes away when the last key is back.
- `sudo manar-edge uninstall` restores every key first and stops if one cannot be restored.
- If the agent dies, the service starts it again within 20 seconds; until then, restore as above.
- If the service is stopped, the socket is gone, the snippet leaves your old agent in place, and
  `sudo manar-edge vault restore --all` puts the keys back.
