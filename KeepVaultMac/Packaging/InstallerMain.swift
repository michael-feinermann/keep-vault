import AppKit
import Foundation
import Security
import Darwin

private let installerIdentifier = "de.michael-feinermann.keep-vault.installer"
private let appleTeam = "2T6K9PGS55"
// CSCommon.h: kSecCodeSignatureRuntime; this constant is absent in some Swift overlays.
private let hardenedRuntimeFlag: UInt32 = 0x10000
private struct InstallFailure: Error { let text: String }
private struct RunningBinding {
    let baseRequirement: String
    let pinnedRequirement: String
    let architecture: String
}

private let packageNames: [String] = {
    let suffixes = [".sha3", ".skein", ".khsig", ".sha3.khsig", ".skein.khsig"]
    return ["Keep Vault.app", "QR-Scanner.app", "Keep Vault Installer.app", "INSTALLATION.txt", "installation-manifest.json"]
        + suffixes.map { "Keep Vault.app.launcher" + $0 }
        + suffixes.map { "QR-Scanner.app" + $0 }
        + suffixes.map { "installation-manifest.json" + $0 }
}()

private func shellQuote(_ value: String) -> String {
    "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
}

private func appleScriptQuote(_ value: String) -> String {
    "\"" + value.replacingOccurrences(of: "\\", with: "\\\\")
        .replacingOccurrences(of: "\"", with: "\\\"")
        .replacingOccurrences(of: "\r", with: "\\r")
        .replacingOccurrences(of: "\n", with: "\\n") + "\""
}

/// Authenticate the running code, not just a pathname a different process can replace.
private func runningRequirement() throws -> RunningBinding {
    let base = "identifier \"\(installerIdentifier)\" and anchor apple generic and certificate leaf[subject.OU] = \"\(appleTeam)\" and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
    var requirement: SecRequirement?
    guard SecRequirementCreateWithString(base as CFString, SecCSFlags(), &requirement) == errSecSuccess,
          let requirement else { throw InstallFailure(text: "Invalid installer signing policy.") }
    var code: SecCode?
    guard SecCodeCopySelf(SecCSFlags(), &code) == errSecSuccess, let code,
          SecCodeCheckValidity(code, SecCSFlags(rawValue: UInt32(kSecCSStrictValidate)), requirement) == errSecSuccess
    else { throw InstallFailure(text: "The running installer does not satisfy its Developer ID policy.") }
    // A static reference obtained from a running process is only a disk hash
    // candidate. Apple's API explicitly does not guarantee a secure link here.
    var staticCandidate: SecStaticCode?
    guard SecCodeCopyStaticCode(code, SecCSFlags(), &staticCandidate) == errSecSuccess,
          let staticCandidate else { throw InstallFailure(text: "Cannot locate the active installer code signature.") }
    var signing: CFDictionary?
    guard SecCodeCopySigningInformation(staticCandidate, SecCSFlags(rawValue: UInt32(kSecCSSigningInformation)), &signing) == errSecSuccess,
          let info = signing as? [String: Any],
          let hash = info[kSecCodeInfoUnique as String] as? Data, hash.count == 20,
          let signatureFlags = info[kSecCodeInfoFlags as String] as? NSNumber,
          (signatureFlags.uint32Value & hardenedRuntimeFlag) != 0
    else { throw InstallFailure(text: "The running installer identity could not be bound.") }
    let hex = hash.map { String(format: "%02x", $0) }.joined()
    let pinnedText = "\(base) and cdhash H\"\(hex)\""
    var pinned: SecRequirement?
    guard SecRequirementCreateWithString(pinnedText as CFString, SecCSFlags(), &pinned) == errSecSuccess,
          let pinned,
          SecCodeCheckValidity(code, SecCSFlags(rawValue: UInt32(kSecCSStrictValidate)), pinned) == errSecSuccess else {
        throw InstallFailure(text: "The on-disk signature candidate does not match the actually running installer.")
    }
    #if arch(arm64)
    let architecture = "arm64"
    #elseif arch(x86_64)
    let architecture = "x86_64"
    #else
    #error("The installer supports only macOS arm64 and x86_64.")
    #endif
    return RunningBinding(baseRequirement: base, pinnedRequirement: pinnedText, architecture: architecture)
}

private func administrator(_ command: String) throws -> String {
    let shell = "/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/zsh -f -c " + shellQuote(command)
    guard let script = NSAppleScript(source: "do shell script " + appleScriptQuote(shell) + " with administrator privileges")
    else { throw InstallFailure(text: "The macOS authorization request could not be prepared.") }
    var error: NSDictionary?
    let result = script.executeAndReturnError(&error)
    if let error { throw InstallFailure(text: error[NSAppleScript.errorMessage] as? String ?? "macOS authorization failed.") }
    return result.stringValue ?? ""
}

private struct StagedPackage {
    let root: String
    let identity: String
    var package: String { root + "/package" }
}

private func incompletePackageMessage(english: Bool) -> String {
    english
        ? "Extract the complete release ZIP into its own folder and keep every package file together. Then select that folder."
        : "Entpacke das vollständige Release-ZIP in einen eigenen Ordner und lasse alle Paketdateien zusammen. Wähle anschließend diesen Ordner aus."
}

/// Validate an explicitly selected complete package without guessing an original
/// path or changing Gatekeeper state when the running app is translocated.
private func checkedPackageSource(_ directory: URL) throws -> String {
    let source = directory.standardizedFileURL.path
    guard source.unicodeScalars.allSatisfy({ $0.value >= 32 && $0.value != 127 }),
          URL(fileURLWithPath: source).resolvingSymlinksInPath().path == source else {
        throw InstallFailure(text: "The package path contains a symbolic link or unsupported control characters.")
    }
    let sourceNames = try FileManager.default.contentsOfDirectory(atPath: source)
    guard Set(sourceNames.filter { $0 != ".DS_Store" }) == Set(packageNames) else {
        throw InstallFailure(text: incompletePackageMessage(english: Locale.preferredLanguages.first?.hasPrefix("de") != true))
    }
    for name in packageNames {
        var metadata = stat()
        guard lstat(source + "/" + name, &metadata) == 0 else {
            throw InstallFailure(text: "A package object cannot be inspected: " + name)
        }
        let directory = name.hasSuffix(".app")
        guard (metadata.st_mode & mode_t(S_IFMT)) == mode_t(directory ? S_IFDIR : S_IFREG),
              directory || metadata.st_nlink == 1 else {
            throw InstallFailure(text: "A package object has an unsafe type or link count: " + name)
        }
    }
    if sourceNames.contains(".DS_Store") {
        var metadata = stat()
        guard lstat(source + "/.DS_Store", &metadata) == 0,
              (metadata.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG),
              metadata.st_nlink == 1, metadata.st_size >= 0, metadata.st_size <= 1_048_576 else {
            throw InstallFailure(text: "The Finder metadata file is unsafe; extract a fresh copy of the complete ZIP.")
        }
    }
    return source
}

@MainActor
private func locatePackageSource(for bundle: URL) throws -> String {
    if let adjacent = try? checkedPackageSource(bundle.deletingLastPathComponent()) { return adjacent }
    let english = Locale.preferredLanguages.first?.hasPrefix("de") != true
    let panel = NSOpenPanel()
    panel.title = english ? "Select the Keep Vault installation folder" : "Keep-Vault-Installationsordner auswählen"
    panel.message = english
        ? "Select the folder containing all files from the extracted Keep Vault ZIP. The complete package will be verified before installation."
        : "Wähle den Ordner mit allen Dateien aus dem entpackten Keep-Vault-ZIP. Der vollständige Installationssatz wird vor der Installation geprüft."
    panel.prompt = english ? "Select folder" : "Ordner auswählen"
    panel.canChooseDirectories = true
    panel.canChooseFiles = false
    panel.allowsMultipleSelection = false
    panel.canCreateDirectories = false
    panel.treatsFilePackagesAsDirectories = false
    guard panel.runModal() == .OK, let selected = panel.url else {
        throw InstallFailure(text: english ? "Folder selection cancelled. No application was installed." : "Ordnerauswahl abgebrochen. Es wurde keine App installiert.")
    }
    return try checkedPackageSource(selected)
}

/// Only system copy/metadata tools run before the immutable copy is authenticated.
/// No application, rollback floor or ZPAQ anchor is changed by this staging step.
@MainActor
private func stagePackage() throws -> StagedPackage {
    guard geteuid() != 0, geteuid() == getuid() else {
        throw InstallFailure(text: "Start the installer as your signed-in user, without sudo.")
    }
    let requirement = try runningRequirement()
    let bundle = Bundle.main.bundleURL.standardizedFileURL
    guard bundle.lastPathComponent == "Keep Vault Installer.app" else {
        throw InstallFailure(text: "Keep the installer in the complete extracted release package.")
    }
    let source = try locatePackageSource(for: bundle)
    let command = try stageCommand(source: source, uid: getuid(), binding: requirement)
    return try parseStagedPackage(administrator(command))
}

private func aclUserName(for uid: uid_t) throws -> String {
    let capacity = 16384
    var entry = passwd()
    var found: UnsafeMutablePointer<passwd>?
    var buffer = [CChar](repeating: 0, count: capacity)
    guard getpwuid_r(uid, &entry, &buffer, capacity, &found) == 0,
          found != nil, entry.pw_uid == uid, let accountName = entry.pw_name else {
        throw InstallFailure(text: "The signed-in user could not be bound to an access-control identity.")
    }
    let name = String(cString: accountName)
    guard !name.isEmpty, !name.contains(":"),
          name.unicodeScalars.allSatisfy({ !CharacterSet.whitespacesAndNewlines.contains($0) && !CharacterSet.controlCharacters.contains($0) }) else {
        throw InstallFailure(text: "The signed-in account name cannot be represented safely in a macOS access-control entry.")
    }
    var reverse = passwd()
    var reverseFound: UnsafeMutablePointer<passwd>?
    var reverseBuffer = [CChar](repeating: 0, count: capacity)
    guard getpwnam_r(name, &reverse, &reverseBuffer, capacity, &reverseFound) == 0,
          reverseFound != nil, reverse.pw_uid == uid else {
        throw InstallFailure(text: "The signed-in account name no longer matches its user ID.")
    }
    return name
}

private func stageCommand(source: String, uid: uid_t, binding: RunningBinding) throws -> String {
    let aclUser = try aclUserName(for: uid)
    return """
    set -euo pipefail
    umask 077
    export PATH=/usr/bin:/bin:/usr/sbin:/sbin
    [[ ! -L /private/tmp && -d /private/tmp && $(/usr/bin/stat -f '%u:%p' /private/tmp) == 0:41777 ]]
    package_stage=$(/usr/bin/mktemp -d /private/tmp/keep-vault-package.XXXXXXXX)
    /bin/chmod -N "$package_stage"
    /bin/chmod 0700 "$package_stage"
    package_stage_identity=$(/usr/bin/stat -f '%d:%i' "$package_stage")
    TRAPEXIT() {
      local package_exit=$?
      if (( package_exit != 0 )); then
        if [[ ! -L "$package_stage" && -d "$package_stage" && $(/usr/bin/stat -f '%u:%d:%i' "$package_stage") == "0:$package_stage_identity" ]]; then
          /bin/rm -rf -- "$package_stage"
        fi
      fi
      return $package_exit
    }
    package_source=\(shellQuote(source))
    /bin/mkdir -m 0700 "$package_stage/package"
    for package_name in \(packageNames.map(shellQuote).joined(separator: " ")); do
      [[ -e "$package_source/$package_name" && ! -L "$package_source/$package_name" ]]
      /usr/bin/ditto --noacl "$package_source/$package_name" "$package_stage/package/$package_name"
    done
    # Reject unsafe object types before recursive owner/ACL changes. Only a
    # root-owned mode-0700 parent can access the copy during this preparation.
    package_unsafe=$(/usr/bin/find "$package_stage/package" \\( -type l -o -type f -links +1 -o ! -type f ! -type d -o -perm -022 \\) -print -quit)
    [[ -z "$package_unsafe" ]]
    /usr/sbin/chown -R -P 0:0 "$package_stage"
    /bin/chmod -RN "$package_stage"
    package_foreign_owner=$(/usr/bin/find "$package_stage" ! -user root -print -quit)
    [[ -z "$package_foreign_owner" ]]
    /usr/bin/codesign --verify --strict --deep --all-architectures -R \(shellQuote("=" + binding.baseRequirement)) "$package_stage/package/Keep Vault Installer.app"
    /usr/bin/codesign --verify --strict --architecture \(shellQuote(binding.architecture)) -R \(shellQuote("=" + binding.pinnedRequirement)) "$package_stage/package/Keep Vault Installer.app"
    # Keep the exact signed POSIX modes; grant this user only the access needed
    # to read the public package and execute its Apple-authenticated tools.
    # Finish access metadata before policy assessment or native execution can
    # place the application under macOS application-management protection.
    package_acl_user=\(shellQuote(aclUser))
    package_acl_uid=\(uid)
    [[ "$(/usr/bin/id -u -- "$package_acl_user")" == "$package_acl_uid" ]]
    /usr/bin/find "$package_stage" -type d -exec /bin/chmod +a \(shellQuote("user:\(aclUser) allow list,search,readattr,readextattr,readsecurity")) {} +
    /usr/bin/find "$package_stage" -type f -exec /bin/chmod +a \(shellQuote("user:\(aclUser) allow read,readattr,readextattr,readsecurity")) {} +
    /usr/bin/find "$package_stage" -type f -perm -0100 -exec /bin/chmod +a \(shellQuote("user:\(aclUser) allow execute")) {} +
    [[ "$(/usr/bin/id -u -- "$package_acl_user")" == "$package_acl_uid" ]]
    /usr/bin/syspolicy_check distribution "$package_stage/package/Keep Vault Installer.app" --verbose >&2
    "$package_stage/package/Keep Vault Installer.app/Contents/MacOS/Keep Vault Release Verifier" verify-installation --root "$package_stage/package" --require-root-owned >"$package_stage/verification.log" 2>&1
    /usr/bin/printf '%s\\t%s' "$package_stage" "$(/usr/bin/stat -f '%d:%i' "$package_stage")"
    """
}

private func parseStagedPackage(_ output: String) throws -> StagedPackage {
    let fields = output.split(separator: "\t", omittingEmptySubsequences: false)
    guard fields.count == 2, fields[0].hasPrefix("/private/tmp/keep-vault-package."),
          fields[0].dropFirst("/private/tmp/keep-vault-package.".count).count == 8,
          fields[0].dropFirst("/private/tmp/keep-vault-package.".count).allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) }),
          fields[1].split(separator: ":", omittingEmptySubsequences: false).count == 2,
          fields[1].split(separator: ":", omittingEmptySubsequences: false).allSatisfy({ !$0.isEmpty && $0.allSatisfy({ $0.isASCII && $0.isNumber }) }) else {
        throw InstallFailure(text: "The authenticated staging result was invalid. No application was installed.")
    }
    return StagedPackage(root: String(fields[0]), identity: String(fields[1]))
}

private func runInstaller(_ staged: StagedPackage) throws -> String {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/zsh")
    process.arguments = ["-f", staged.package + "/Keep Vault Installer.app/Contents/Resources/tools/Install-KeepVault-macOS.sh",
                         "--package-root", staged.package, "--no-desktop-alias"]
    process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": NSHomeDirectory(),
                           "USER": NSUserName(), "LOGNAME": NSUserName(), "TMPDIR": "/private/tmp"]
    let output = Pipe()
    process.standardOutput = output
    process.standardError = output
    process.standardInput = FileHandle.nullDevice
    try process.run()
    // Continuously drain the pipe so the installer's diagnostics cannot block it.
    var log = Data()
    while true {
        let chunk = output.fileHandleForReading.availableData
        if chunk.isEmpty { break }
        if log.count < 131_072 { log.append(chunk.prefix(131_072 - log.count)) }
    }
    process.waitUntilExit()
    let text = String(decoding: log, as: UTF8.self)
    guard process.terminationReason == .exit && process.terminationStatus == 0 else {
        throw InstallFailure(text: "Installer exit \(process.terminationStatus).\n\(text)\nStaging: \(staged.root)")
    }
    return text
}

private func removeStaging(_ staged: StagedPackage) throws {
    let command = """
    set -euo pipefail
    export PATH=/usr/bin:/bin:/usr/sbin:/sbin
    package_stage=\(shellQuote(staged.root))
    [[ ! -L "$package_stage" && -d "$package_stage" ]]
    [[ $(/usr/bin/stat -f '%u:%d:%i' "$package_stage") == \(shellQuote("0:" + staged.identity)) ]]
    /bin/rm -rf -- "$package_stage"
    """
    _ = try administrator(command)
}

@MainActor
private func makeInstallerResultAlert(success: Bool, text: String, english: Bool) -> NSAlert {
    let alert = NSAlert()
    alert.alertStyle = success ? .informational : .warning
    alert.messageText = success
        ? (english ? "Installation completed" : "Installation abgeschlossen")
        : (english ? "Installation stopped" : "Installation angehalten")
    alert.addButton(withTitle: "OK")

    // Keep short messages directly readable. A bounded viewport prevents a
    // process log or a long path from expanding the alert beyond the screen.
    if text.utf16.count <= 400 && text.components(separatedBy: .newlines).count <= 6 {
        alert.informativeText = text
        return alert
    }
    alert.informativeText = english
        ? "You can read, select and copy the details in the scrollable field below."
        : "Die Details kannst du im scrollbaren Feld unten lesen, markieren und kopieren."
    let scrollView = NSScrollView(frame: NSRect(x: 0, y: 0, width: 600, height: 240))
    scrollView.hasVerticalScroller = true
    scrollView.hasHorizontalScroller = false
    scrollView.borderType = .bezelBorder
    let textView = NSTextView(frame: NSRect(origin: .zero, size: scrollView.contentSize))
    textView.isEditable = false
    textView.isSelectable = true
    textView.isRichText = false
    textView.importsGraphics = false
    textView.allowsUndo = false
    textView.font = NSFont.systemFont(ofSize: 13)
    textView.textColor = .textColor
    textView.backgroundColor = .textBackgroundColor
    textView.textContainerInset = NSSize(width: 8, height: 8)
    textView.minSize = NSSize(width: 0, height: scrollView.contentSize.height)
    textView.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
    textView.isHorizontallyResizable = false
    textView.isVerticallyResizable = true
    textView.autoresizingMask = [.width]
    textView.textContainer?.widthTracksTextView = true
    textView.textContainer?.containerSize = NSSize(width: scrollView.contentSize.width, height: CGFloat.greatestFiniteMagnitude)
    textView.setAccessibilityLabel(english ? "Installation details" : "Installationsdetails")
    textView.string = text
    scrollView.documentView = textView
    textView.sizeToFit()
    alert.accessoryView = scrollView
    return alert
}

@MainActor
private final class InstallerDelegate: NSObject, NSApplicationDelegate {
    private let english = Locale.preferredLanguages.first?.hasPrefix("de") != true
    private var window: NSWindow?
    private var status: NSTextField?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.activate(ignoringOtherApps: true)
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? ""
        let alert = NSAlert()
        alert.messageText = "Keep Vault \(version)"
        alert.informativeText = english
            ? "Install Keep Vault and QR-Scanner in Applications. macOS administrator authorization is required to protect the installation files and set up the verified archive component."
            : "Keep Vault und QR-Scanner unter Programme installieren. Die macOS-Administratorfreigabe wird benötigt, um die Installationsdateien zu schützen und die geprüfte Archivkomponente einzurichten."
        alert.addButton(withTitle: english ? "Install" : "Installieren")
        alert.addButton(withTitle: english ? "Cancel" : "Abbrechen")
        guard alert.runModal() == .alertFirstButtonReturn else { NSApp.terminate(nil); return }
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 560, height: 160), styleMask: [.titled], backing: .buffered, defer: false)
        window.title = "Keep Vault \(version)"
        let label = NSTextField(wrappingLabelWithString: english ? "Verifying and preparing installation…" : "Installation wird geprüft und vorbereitet …")
        label.font = NSFont.systemFont(ofSize: 17)
        label.frame = NSRect(x: 24, y: 44, width: 512, height: 78)
        window.contentView?.addSubview(label)
        window.center(); window.makeKeyAndOrderFront(nil)
        self.window = window; self.status = label
        // Authorization is deliberately a standard local macOS prompt.
        // Passwords never pass through application fields, logs or arguments.
        DispatchQueue.main.async { self.beginInstallation() }
    }

    private func beginInstallation() {
        do {
            let staged = try stagePackage()
            status?.stringValue = english ? "Installing verified applications…" : "Geprüfte Apps werden installiert …"
            DispatchQueue.global(qos: .userInitiated).async {
                let result = Result { try runInstaller(staged) }
                DispatchQueue.main.async {
                    switch result {
                    case .success:
                        do {
                            try removeStaging(staged)
                            self.finish(success: true, text: self.english ? "Keep Vault and QR-Scanner are installed in Applications." : "Keep Vault und QR-Scanner sind unter Programme installiert.")
                        } catch {
                            self.finish(success: true, text: (self.english ? "Installation completed. The protected temporary package was preserved at: " : "Installation abgeschlossen. Das geschützte temporäre Paket wurde aufbewahrt unter: ") + staged.root)
                        }
                    case .failure(let error): self.finish(success: false, text: (error as? InstallFailure)?.text ?? error.localizedDescription)
                    }
                }
            }
        } catch { finish(success: false, text: (error as? InstallFailure)?.text ?? error.localizedDescription) }
    }

    private func finish(success: Bool, text: String) {
        window?.close()
        let alert = makeInstallerResultAlert(success: success, text: text, english: english)
        alert.runModal()
        NSApp.terminate(nil)
    }
}

@main
private struct InstallerMain {
    @MainActor static func main() {
        guard CommandLine.arguments.count == 1 else {
            FileHandle.standardError.write(Data("Start Keep Vault Installer without command-line arguments.\n".utf8))
            exit(64)
        }
        let application = NSApplication.shared
        let delegate = InstallerDelegate()
        application.delegate = delegate
        application.setActivationPolicy(.regular)
        application.run()
    }
}
