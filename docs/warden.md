# WARDEN: the desktop prompt (spec 4.6)

WARDEN shows "Cursor wants to read ~/.aws/credentials" with Approve once / For 8 hours / Deny, in English
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
- **Secrets vault API**: `warden.AskSecret(ctx, program, secretName) (Decision, error)`. Treat
  `ErrNoHelper`, `Dismissed` and any error as a refusal. The vault remembers an `approve_8h` itself.
- Sound is off.
