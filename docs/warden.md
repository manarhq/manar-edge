# WARDEN: the desktop prompt (spec 4.6)

WARDEN shows "Cursor wants to read ~/.aws/credentials" with Approve once / Deny, in English
or Arabic (from the user's locale). Product name WARDEN, subtitle "Manar app on this device".

- **Service side** (`internal/warden`, a `daemon.Module`): polls `GET /host/v1/approvals/pending` every 3 s,
  asks the helper, and sends `POST /host/v1/approvals/:id/decide` over the host mTLS channel
  (`hostclient`). The helper never talks to the API. A prompt is never shown for, and a decision is
  never sent for, a high-risk action or when the owner may not approve (the API says so in
  `decidableHere`): those say "Open the console to decide".
- **Helper** (`manar-edge warden`, per user, started at logon): connects to the service and shows the prompt.
  - Linux: unix socket `/run/manar-edge/warden.sock`, SO_PEERCRED check (root and the uids in
    `<state>/warden/allowed-uids`, written at install from `SUDO_UID`). Prompt is an
    `org.freedesktop.Notifications` notification with actions (godbus). Autostart:
    `/etc/xdg/autostart/manar-warden.desktop`.
  - Windows: named pipe `\\.\pipe\manar-warden` whose DACL allows only SYSTEM and the installing
    user's SID (`<state>\warden\user-sid`). Toast through the Windows Runtime
    (`git.sr.ht/~jackmordaunt/go-toast/v2`, no PowerShell for the toast). Autostart: HKCU Run.
    **Off by default**: `manar-edge warden windows-ui on` (administrator) turns it on. It builds and
    its mapping is unit tested, but it has not been run on a real desktop.
- **Closing or ignoring a prompt approves nothing.** The approval stays pending and expires.
- **Secrets vault API**: `warden.AskSecret(ctx, program, secretName) (Decision, error)` opens a
  console-only approval (`POST /host/v1/approvals/vault`) and waits for a signed-in person to decide
  it. The desktop only says "Open the console to decide": a desktop answer is never consent for a
  secret. Treat `ErrNoHelper`, `Dismissed` and any error as a refusal. The vault remembers an
  `approve_8h` itself.
- **A device answers once or deny.** "For 8 hours" is a console decision (a browser session): the
  API refuses `approve_8h` from a device and the service drops it if a helper sends it. This differs
  from the mockup's toast, which shows three buttons; two is the safe version.
- Sound is off.

## Who may be the helper

- One helper per session: a second connection never replaces the first.
- Linux: the peer must pass SO_PEERCRED (root or an allowed uid) **and** its `/proc/<pid>/exe` must be
  exactly the installed manar-edge binary, which and whose directory must be root-owned and not
  writable by group or others. A program of the same user (the AI tool, a postinstall script) that
  opens the socket is refused.
- Windows: the pipe's DACL gives the user read and write but not the right to create pipe instances
  (`0x12019b`, no `FILE_CREATE_PIPE_INSTANCE`), so no fake server next to the real one. The service
  checks the client's image path; the helper checks the server's.
- D-Bus: action signals are believed only from the current owner of
  `org.freedesktop.Notifications`, and only for the notification id we created.

## Residual risk

A desktop prompt cannot be fully protected from code running as the same user. That code shares the
user's session and can, for example, attach a debugger to the real helper, set `LD_PRELOAD`, or click
the notification through accessibility APIs. The checks above remove the easy attacks (opening the
socket, running a fake server, forging signals). What stays in scope for a device decision is small
on purpose: approve **once**, never a standing permission, never a secret, and never a high-risk
action. Those need the console.
