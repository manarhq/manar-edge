# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it privately, by either route:

1. **GitHub Security Advisories.** Open this repository's **Security** tab and choose
   **Report a vulnerability**. This creates a private advisory that only the maintainers can see.
2. **Email** security@fixio.ae. Put the repository name in the subject. If you need an
   encrypted channel, say so in a first message without details and we will arrange one.

Please include what you found, the version or commit, steps to reproduce, and the impact you
expect. Do not include real customer data or third-party secrets.

## What to expect

| Step | Target |
| --- | --- |
| Acknowledge your report | 3 business days |
| First assessment (accepted, needs more information, or not a vulnerability) | 7 days |
| Fix or mitigation for a confirmed critical or high issue | 30 days |
| Fix for a confirmed medium or low issue | next regular release |

These are targets for a small team, not a contract. We will tell you if one is going to slip.
We will credit you in the advisory unless you ask us not to.

## Supported versions

Manar has not had a 1.0 release. Security fixes go to the latest release and to `main`.
Older releases are not patched.

## Scope

In scope: the code in this repository. Out of scope: vulnerabilities in third-party
dependencies that are not exploitable through this code (report those upstream), social
engineering, and denial of service by sheer traffic volume.

Please act in good faith: do not access data that is not yours, do not degrade a service
that you do not own, and give us a reasonable time to fix the issue before you publish it.
