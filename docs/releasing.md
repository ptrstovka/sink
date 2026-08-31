# Release guide

GitHub's `Release binaries` workflow builds the macOS and Linux archives. The
two macOS jobs sign `sink` and `sink-server` with a Developer ID Application
certificate, submit the signed files to Apple's notary service, and publish the
archive only after Apple returns `Accepted`.

The binary matrix has exactly four native lanes:

- `aarch64-apple-darwin` (`macos-arm64`)
- `x86_64-apple-darwin` (`macos-x86_64`)
- `aarch64-unknown-linux-musl` (`linux-arm64`)
- `x86_64-unknown-linux-musl` (`linux-x86_64`)

Every lane uses Node 24 with its bundled npm and the package-lock v3 file as the
npm cache key input. It runs this order once before Cargo:

```console
cd dashboard
npm ci
npm run verify
cd ..
cargo build --release --locked --target TARGET --bin sink --bin sink-server
```

`npm run verify` already runs the Vitest and production-source guard through
`npm test`, then typechecking, the Vite production build, and the
production-bundle guard through `npm run build`. Do not duplicate or bypass
those guards. The resulting `dashboard/dist` is generated once and kept
unchanged for the job's release Cargo build. Cargo only consumes and embeds
those bytes; it must not invoke npm or fetch frontend assets.

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

The workflow performs this sequence for each macOS architecture after the
frontend verification and locked Cargo build:

1. Import the `.p12` into a temporary runner keychain.
2. Sign both executables with the hardened runtime and a secure timestamp.
3. Verify both signatures with `codesign`.
4. Submit a temporary ZIP to `notarytool` and wait for completion.
5. Print Apple's notarization log and require an `Accepted` result.
6. Create the release `.tar.gz` from the exact signed, accepted bytes.
7. Extract the archive on its native runner and require both `sink version` and
   `sink-server version` to match the release tag.
8. Delete the temporary certificate, API key, and keychain.

Linux follows the same build, package, archive, and native binary-version
verification without Apple operations. The native Linux x86_64 lane also copies
the unpacked `sink` into an isolated directory and runs it from an empty working
directory with a PATH containing no Node.js. It uses an explicit loopback
dashboard port and an unreachable loopback control endpoint, then requires the
packaged binary to serve embedded HTML, a hashed JavaScript asset, and
`/api/v1/transactions`. Finally it sends SIGTERM, requires a clean exit, and
proves that the dashboard port can be rebound. The smoke uses no repository or
Apple secrets.

If signing or notarization fails, the macOS matrix jobs fail and the publish job
doesn't attach any rebuilt release archives.

The release workflow is unchanged for client self-update. `sink update`
considers the latest stable release ready for a platform only after both that
platform's exact archive and `SHA256SUMS` are attached. This avoids treating the
release as installable during the window after publication but before all
assets finish uploading. A missing archive or checksum file makes that release
unavailable to the client rather than partially ready.

During installation, the client verifies the archive's GitHub asset digest,
its entry in `SHA256SUMS`, and the staged `sink version` before replacing the
installed client. It extracts only `sink`; release archives and the workflow
continue to include `sink-server` independently.

After configuring the secrets, use the workflow's `Run workflow` action with an
existing release tag to replace that release's unsigned archives. New published
releases use the same workflow automatically.

This is a binary-release workflow from a full repository checkout. Publishing
the Cargo workspace or `sink-client` as a crates.io/source package is out of
scope: ignored `dashboard/dist` is deliberately prebuilt and is not included in
a Cargo source archive. Supporting source packages would require a separate,
explicit asset-packaging design. Running the workflow, publishing assets, and
the manual one-hour soak are release-operator gates; documentation or CI
changes do not claim they have run. They also do not claim that a live update
against a published release or an in-place replacement was exercised.

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
