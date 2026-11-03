# Trusting the Manar edge on Windows (for customer IT)

The Windows build of the Manar edge (`manar-edge-windows-amd64.exe`) is Authenticode-signed by
**Fixio Technologies LLC SPC**, the company behind Manar. The certificate is Fixio's own: it is not
issued by a public certificate authority. A Windows device therefore shows "Unknown publisher" until
your IT team tells it to trust this certificate. This page explains how to do that with Intune or
Group Policy, and how to check a download by hand.

## What you trust

| | |
|---|---|
| Subject | `CN=Fixio Technologies LLC SPC, O=Fixio Technologies LLC SPC, C=AE` |
| Type | Self-signed, code signing only: Extended Key Usage *Code Signing*, Key Usage *Digital Signature* |
| Can it issue certificates? | No. It is not a CA certificate, so trusting it lets Windows accept code that Fixio signed and nothing else. |
| Validity | 36 months. Fixio sends the next certificate at least 90 days before expiry. |
| Private key | Held in an HSM-backed Azure Key Vault in UAE North. It is never exported. |
| File | `fixio-code-signing.cer`, attached to every signed release on the manar-edge GitHub releases page |

**Check the thumbprint before you deploy it.** Compare the SHA-1 thumbprint of the `.cer` file with
the one your Fixio account contact gives you outside the download (email or a call, not the
download page). Don't trust a certificate whose thumbprint you have not compared.

```powershell
(Get-PfxCertificate -FilePath .\fixio-code-signing.cer).Thumbprint
```

## Which stores

| Store | Why |
|---|---|
| **Trusted Root Certification Authorities** (Local Computer) | Windows builds the signature chain to a trusted root. Without it the signature shows "not trusted" and UAC shows "Unknown publisher". |
| **Trusted Publishers** (Local Computer) | Marks Fixio as a publisher you accept, so you don't get a per-user prompt. It is needed by policies that check this store, for example PowerShell `AllSigned`. |

Use the computer stores, not the user stores, so the trust applies to every account on the device,
including the service the edge installs.

## Intune

1. **Root store**: Devices → Configuration → Create → New policy. Platform *Windows 10 and later*,
   profile type *Templates* → *Trusted certificate*.
   - Upload `fixio-code-signing.cer`.
   - Destination store: *Computer certificate store - Root*.
   - Assign the profile to the device groups that run the Manar edge.
2. **Trusted Publishers**: the Trusted certificate template has no Trusted Publishers option, so use
   a custom profile (Templates → *Custom*) with one OMA-URI setting:
   - OMA-URI: `./Device/Vendor/MSFT/RootCATrustedCertificates/TrustedPublisher/<THUMBPRINT>/EncodedCertificate`
     (`<THUMBPRINT>`: the SHA-1 thumbprint, upper case, no spaces)
   - Data type: *String*
   - Value: the certificate as one line of Base64 (DER):

     ```powershell
     [Convert]::ToBase64String([IO.File]::ReadAllBytes(".\fixio-code-signing.cer"))
     ```
3. Assign both profiles to the same groups. Check a device under Devices → *device* → Device
   configuration: both profiles must show *Succeeded*.

If you deploy the edge as an Intune Win32 app, the installer runs without the "downloaded from the
internet" mark, so SmartScreen does not prompt. The signature is still checked against the stores above.

## Group Policy (Active Directory)

1. In Group Policy Management, create or edit a GPO linked to the OU that holds the devices.
2. Computer Configuration → Policies → Windows Settings → Security Settings → Public Key Policies:
   - **Trusted Root Certification Authorities** → right-click → *Import* → `fixio-code-signing.cer`;
   - **Trusted Publishers** → right-click → *Import* → the same file.
3. Run `gpupdate /force` on a test device, or wait for the next refresh.

Without a domain, for a single device in an elevated PowerShell:

```powershell
Import-Certificate -FilePath .\fixio-code-signing.cer -CertStoreLocation Cert:\LocalMachine\Root
Import-Certificate -FilePath .\fixio-code-signing.cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
```

## Allow-listing (WDAC, AppLocker)

With the certificate trusted, you can allow the edge by publisher instead of by file hash, so you
don't have to update a rule on every release.

- **AppLocker**: Executable Rules → *Create New Rule* → *Publisher*, using a signed
  `manar-edge-windows-amd64.exe` as the reference. Publisher: `O=FIXIO TECHNOLOGIES LLC SPC, ...`.
- **App Control for Business (WDAC)**: add a signer rule for the certificate, for example
  `New-CIPolicyRule -Level Publisher -DriverFilePath .\manar-edge-windows-amd64.exe`, then merge it into your policy.

## Checking a download by hand

```powershell
Get-AuthenticodeSignature .\manar-edge-windows-amd64.exe | Format-List Status, SignerCertificate
```

`Status` must be `Valid`, and `SignerCertificate.Thumbprint` must match the thumbprint Fixio gave you.

Every release also has `SHA256SUMS`, signed with the Manar edge release key. This covers the Windows and
Linux binaries and the `.cer` file. With [cosign](https://github.com/sigstore/cosign) and the
`cosign-edge.pub` from the release, after you compare its fingerprint
(`sha256sum cosign-edge.pub`) with the one Fixio gives you:

```bash
cosign verify-blob --key cosign-edge.pub --bundle SHA256SUMS.sigstore.json \
  --insecure-ignore-tlog=true SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

`--insecure-ignore-tlog` is expected: Manar signs offline and does not publish to a public
transparency log. The trust comes from the key fingerprint you compared.

## Certificate renewal and removal

- **Renewal:** Fixio sends the next `.cer` and its thumbprint at least 90 days before the current
  one expires. Deploy it alongside the old one; remove the old one after it expires.
- **Expiry:** releases are signed without a timestamp. When a certificate expires, Windows stops
  accepting binaries signed with it. Update the edge to a release signed with the current certificate
  before then.
- **Removal:** delete the Intune profiles or the GPO entries. For a single device, run
  `Get-ChildItem Cert:\LocalMachine\Root, Cert:\LocalMachine\TrustedPublisher | Where-Object Thumbprint -eq '<THUMBPRINT>' | Remove-Item`.
