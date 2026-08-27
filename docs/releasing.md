# Release guide

GitHub's `Release binaries` workflow builds the macOS and Linux archives. The
two macOS jobs sign `sink` and `sink-server` with a Developer ID Application
certificate, submit the signed files to Apple's notary service, and publish the
archive only after Apple returns `Accepted`.

The release remains a `.tar.gz`. Apple publishes notarization tickets online
for the two standalone executables, so they don't need to be wrapped in an app,
disk image, or installer. Standalone binaries can't carry stapled tickets and
therefore need network access the first time Gatekeeper evaluates them.

## One-time Apple setup

### Create the signing certificate

1. In Keychain Access, create a Certificate Signing Request and save it to disk.
2. Open Certificates, Identifiers & Profiles in the Apple Developer account.
3. Add a certificate, select `Developer ID`, then select
   `Developer ID Application` and upload the request.
4. Download and install the certificate in the login keychain.
5. In the `My Certificates` section of Keychain Access, verify that the
   Developer ID certificate expands to show its private key.
6. Export the certificate and private key together as a password-protected
   `.p12` file. Keep a protected backup; Apple can't recover this private key.

The certificate must be a `Developer ID Application` certificate. Development,
App Store distribution, and self-signed certificates don't satisfy Gatekeeper
or the notary service.

### Create the notarization API key

1. In App Store Connect, open `Users and Access`, then `Integrations` and
   `App Store Connect API`.
2. Create a **team API key** with the `Developer` role. Don't use an individual
   API key; `Admin` also works but grants more access than this workflow needs.
3. Download the `.p8` private key immediately. Apple only allows it to be
   downloaded once.
4. Record the key's Key ID and the account's Issuer ID.

## GitHub Actions secrets

Add these repository Actions secrets under `Settings` > `Secrets and
variables` > `Actions`:

| Secret | Value |
| --- | --- |
| `APPLE_DEVELOPER_ID_P12` | Base64-encoded contents of the exported `.p12` file |
| `APPLE_DEVELOPER_ID_P12_PASSWORD` | Password chosen while exporting the `.p12` |
| `APPLE_TEAM_ID` | 10-character Apple Developer Team ID |
| `APPLE_API_KEY_P8` | Complete contents of the downloaded `.p8` file, including its header and footer |
| `APPLE_API_KEY_ID` | App Store Connect API Key ID |
| `APPLE_API_ISSUER_ID` | App Store Connect API Issuer ID |

On macOS, generate the value for `APPLE_DEVELOPER_ID_P12` without modifying the
certificate file:

```console
base64 -i DeveloperIDApplication.p12 | pbcopy
```

Paste the clipboard value into the GitHub secret. Paste the `.p8` file as
multiline text; don't base64-encode it. Delete unprotected temporary copies of
both private keys after the secrets are configured.

## Release behavior

The workflow performs this sequence for each macOS architecture:

1. Import the `.p12` into a temporary runner keychain.
2. Sign both executables with the hardened runtime and a secure timestamp.
3. Verify both signatures with `codesign`.
4. Submit a temporary ZIP to `notarytool` and wait for completion.
5. Print Apple's notarization log and require an `Accepted` result.
6. Create the release `.tar.gz` from the exact signed, accepted bytes.
7. Delete the temporary certificate, API key, and keychain.

If signing or notarization fails, the macOS matrix jobs fail and the publish job
doesn't attach any rebuilt release archives.

After configuring the secrets, use the workflow's `Run workflow` action with an
existing release tag to replace that release's unsigned archives. New published
releases use the same workflow automatically.

## Verify a downloaded release

Download the archive through a browser on a Mac, extract it, then inspect both
executables:

```console
codesign --verify --strict --verbose=2 sink
codesign -dvv sink

codesign --verify --strict --verbose=2 sink-server
codesign -dvv sink-server
```

The `codesign -dvv` output should include `Authority=Developer ID Application`,
the expected Team ID, `Runtime Version`, and a secure `Timestamp`. Run the
browser-downloaded executable normally while online to exercise Gatekeeper's
online ticket lookup. `spctl --assess` isn't a valid post-check for these bare
command-line executables: it can reject successfully notarized code with
`the code is valid but does not seem to be an app` because there is no app
bundle to assess.
