# QR-Scanner

[Deutsch](README.md) | English

Standalone macOS app that reads a QR code through the camera, shows its content
in a text field, and puts it on the clipboard on request. The content is
**not** written to a file.

The app is independent of Keep Vault: its own folder, bundle ID
(`de.michael-feinermann.qr-scanner`), signature, and build. It shares no
application code with Keep Vault and reads nothing from its bundle. The
Keep Vault release build calls the separate scanner build with the same version
and build number. The app itself consists entirely of Swift; for the mandatory
hybrid RSA-PSS/ML-DSA signatures, the build script uses the Keep Vault signer
restored in locked mode using the pinned .NET SDK.

## Building

```bash
./QrCodeScanner/tools/Build-QrScanner-macOS.sh \
  --version 5.0.0 --build-number 12
```

The script builds universally (arm64 + x86_64), runs the tests, generates the
icon, signs with Hardened Runtime and sandboxing, verifies the signature, and
places the verified result in `QrCodeScanner/dist/`.

Installation takes place exclusively together with Keep Vault through
`tools/Install-KeepVault-macOS.sh`. The earlier standalone `--install` path was
removed so that there is only one installation and rollback path for the app
and signature sidecars, bound to objects and hardened against replacement
races. For a joint Keep Vault release, `--version` and `--build-number` must
exactly match the values of the Keep Vault build; the portable package build
rejects missing or mismatched scanner metadata.

On first launch, macOS asks once for camera access. If access is denied, this
can only be reversed in System Settings under “Privacy & Security” › “Camera”.
The app gets no second chance to ask and explains this.

## Which of the two QR codes applies

A key sheet carries the same factor in two QR codes. This is the reason for
the rule, which is written out in full in
[`Sources/CodeArbiter.swift`](Sources/CodeArbiter.swift):

| What the camera sees | What the app does |
| --- | --- |
| Both codes readable, same content | Accepted immediately, “confirmed by 2 codes” |
| One code damaged, one readable | The readable one applies, after 8 identical readings in a row |
| Both codes readable, **different** content | Nothing is accepted; the contradiction is reported |
| Nothing readable | Keep looking |

The decisive point: “error-free” is not something measured afterward. A QR code
carries Reed-Solomon parity, so a decoder does not return damaged content; it
repairs the damage and returns the original, or it fails and returns nothing.
A creased, smeared, or clipped code therefore does not appear among detections
in the first place. The readable code is left over by itself.

That two read codes have the same content is checked, not assumed. If they
contradict each other, any choice would be a guess, and what would be guessed
is half of an archive key. The app reports the contradiction instead.

Two reports of a single code in the same image do not count as two codes:
detections are grouped by position, or the app's strongest confirmation would
rest on a duplicate report.

### Checked against the actual sheets

`tools/scan-file.swift` sends a PDF or image through exactly the same path as
a camera image: the same Vision request, the same `Detection` values, and the
same `CodeArbiter`:

```bash
xcrun swiftc -parse-as-library -O \
  QrCodeScanner/Sources/CodeArbiter.swift \
  QrCodeScanner/Sources/PayloadInspector.swift \
  QrCodeScanner/Sources/Localization.swift \
  QrCodeScanner/tools/scan-file.swift -framework AppKit -o /tmp/scan-file
/tmp/scan-file ~/Downloads/mein-schluesselzettel.pdf
```

On the two example sheets: both codes found, a single distinct payload,
accepted as “confirmed by 2 codes”. If the left code in the image is destroyed,
the app finds only one and internally confirms the same 128-character factor.
The tool never outputs payload content, substrings, or reversible values
derived from it, only lengths, positions, counts, and decision metadata.

## What the app does not write to the SSD

The app has **no** file entitlement, not even `user-selected.read-only`.
It has nothing to read and nothing to write, and the sandbox makes this a
system rule rather than a promise in code. Paths through which AppKit writes
text to disk on its own are also disabled:

- **Window restoration.** `NSWindow.isRestorable = false` and
  `applicationSupportsSecureRestorableState → false`. Otherwise, AppKit stores
  the window content, in this case the scanned value, under
  `~/Library/Saved Application State/`.
- **Spell checking and substitutions.** The checker learns words into the
  user dictionary; substitution logic maintains its own state. Both are
  disabled individually on the text field.
- **Find panel.** `usesFindPanel = false`; otherwise, search history ends up
  in defaults.
- **Data detection.** No automatic link or data detection that passes text
  to other services.
- **Logs.** The content is not logged anywhere.

Measured after a run: no entry in `~/Library/Saved Application State/`,
no `~/Library/Preferences/de.michael-feinermann.qr-scanner.plist`.

## What this app cannot prevent

For the list above to be meaningful, here is the other side stated candidly.

- **The clipboard.** The Copy button is the one place where the value leaves
  the app. The clipboard belongs to the system, not to this app: macOS can
  write it to disk and pass it to other Apple devices through Universal
  Clipboard. No entitlement changes that. What can be done is done: the entry
  is marked as `org.nspasteboard.ConcealedType`, which clipboard managers
  respect, and cleared again after **30 seconds**. It is cleared only if the
  clipboard still contains the same value; if the user has copied something
  else in the meantime, that is left untouched.
- **The sandbox container.** The system creates
  `~/Library/Containers/de.michael-feinermann.qr-scanner/`, not the app.
  A Neural Engine model cache (`com.apple.e5rt.e5bundlecache`) appears in it,
  compiled by the Vision framework on the first run. This is framework
  machinery and contains no scanned content, but it is a file and is therefore
  listed here.
- **Paging and crash reports.** The value is in memory. The app does not decide
  what macOS writes from it to the encrypted swap area or includes in a crash
  report.
- **The camera sees the sheet.** A printed sheet in front of a lens is visible
  to the camera and everything else in the room.

## Apple compliance

The app is sandboxed, runs under Hardened Runtime, and declares exactly two
entitlements: `app-sandbox` and `device.camera`. What is absent is equally
important: `disable-library-validation`, `allow-unsigned-executable-memory`,
`allow-dyld-environment-variables`, and `get-task-allow`. Each allows another
process to inject code into this one, and this is the process holding the
scanned value in memory. The build script aborts if any of them appears in
the entitlements **or** the final signature, and then verifies that sandbox,
camera, and Hardened Runtime are actually enabled.

A publicly distributed app is built exclusively with a `Developer ID
Application` identity from the same team, submitted to Apple's notary service,
stapled, and then checked again with `codesign`, `spctl`, and `stapler`.
A local `Apple Development` signature is permitted only for development gates
and is never presented as a releasable build.

```bash
xcrun notarytool store-credentials "QR-Scanner" \
  --apple-id DEINE-APPLE-ID --team-id TEAM-ID
./QrCodeScanner/tools/Build-QrScanner-macOS.sh --notary-profile "Keep Vault v12"
```

`notarytool` prompts for the app-specific password without displaying it and
stores the profile in Keychain. The build script notarizes, attaches the ticket,
and checks it with `spctl`.
The scanner is installed only through the shared Keep Vault installer.

## Icon

The icon is an actual QR code on a rounded tile and is generated on every
build from [`tools/make-icon.swift`](tools/make-icon.swift), rather than stored
as a binary file in the repository. It encodes “QR-Scanner”; scanning it returns
exactly that. Error correction L on a short string keeps the module count small
(version 1), so the modules remain individually visible even at 16 points
instead of blurring into gray.

## Structure

| File | Content |
| --- | --- |
| `Sources/CodeArbiter.swift` | The rule for which of the two codes applies. Without AppKit, so it remains testable. |
| `Sources/PayloadInspector.swift` | Length limit and notices about invisible characters in the content. |
| `Sources/ScanSession.swift` | Camera and decoding through Vision. |
| `Sources/VolatileClipboard.swift` | Copy with an expiry. |
| `Sources/MainWindowController.swift` | Window; contains the settings against writing to disk. |
| `Sources/App.swift` | Startup, menu, state restoration rejected. |
| `Tests/ArbiterTests.swift` | 26 checks of the rule; run on every build. |
| `tools/scan-file.swift` | Diagnostics: the same evaluation applied to a file. |

## Why detection does not use AVCaptureMetadataOutput

Because it cannot do so on macOS. `AVCaptureMetadataOutput` reads machine-readable
codes only on iOS; on macOS, the same class offers face detection and nothing
else. The mistake is easy to make because the class exists on macOS, compiles
against `.qr`, and then simply never reports a code:
`availableMetadataObjectTypes` never contains `.qr`, even after the session
is running. Detection therefore uses `Vision` (`VNDetectBarcodesRequest`),
which works on macOS and already provides what the rule above needs: each
code in the image separately, with content and position.
