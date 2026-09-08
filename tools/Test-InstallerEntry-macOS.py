#!/usr/bin/env python3
"""Compile actual entry helper functions and test without GUI or authorization.

The harness does not call administrator(), stagePackage(), runInstaller() or
removeStaging(). It tests zsh syntax and literal quoting, and executes only the
actual generated codesign verification lines against its own temporary ad-hoc
signed fixture. Generated ACL commands are tested on private files with no POSIX
access, including read/execute success and denied write access. No release signing
identity, keychain or privilege prompt is used. AppKit presentation tests create
hidden alerts without running a modal loop or activating the application. Pass
--presentation-only to run those tests without signing or executing fixtures.
"""
from pathlib import Path
import argparse
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--presentation-only", action="store_true")
arguments = parser.parse_args()
repo = Path(__file__).resolve().parent.parent
source = (repo / "KeepVaultMac/Packaging/InstallerMain.swift").read_text()
helpers = source[:source.index("\n@MainActor\nprivate final class InstallerDelegate")]
harness = r'''
@main private struct HelperTests {
    static func check(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        if !condition() { throw InstallFailure(text: message) }
    }
    @MainActor static func main() {
        do {
            if CommandLine.arguments.dropFirst() == ["--presentation-only"] {
                try testPresentation()
                print("installer_entry_presentation=passed; languages=2; alert_cases=18; package_messages=2; visible_windows=0")
            } else { try run() }
        }
        catch { FileHandle.standardError.write(Data("\(error)\n".utf8)); exit(1) }
    }
    static func process(_ executable: String, _ arguments: [String]) throws -> (Int32, String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        let pipe = Pipe(); process.standardOutput = pipe; process.standardError = pipe
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(decoding: data, as: UTF8.self))
    }
    static func testActualCodesignRequirements() throws {
        let files = FileManager.default
        let root = URL(fileURLWithPath: "/private/tmp/keep-vault-installer-requirements-" + UUID().uuidString)
        try files.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? files.removeItem(at: root) }
        let bundle = root.appendingPathComponent("package/Keep Vault Installer.app")
        let macOS = bundle.appendingPathComponent("Contents/MacOS")
        try files.createDirectory(at: macOS, withIntermediateDirectories: true)
        let identifier = "de.michael-feinermann.keep-vault.installer-requirement-fixture"
        let executable = "InstallerFixture"
        let metadata: [String: String] = [
            "CFBundleIdentifier": identifier, "CFBundleExecutable": executable,
            "CFBundleName": executable, "CFBundlePackageType": "APPL",
            "CFBundleVersion": "1", "CFBundleShortVersionString": "1.0"
        ]
        let plist = try PropertyListSerialization.data(fromPropertyList: metadata, format: .xml, options: 0)
        try plist.write(to: bundle.appendingPathComponent("Contents/Info.plist"), options: .withoutOverwriting)
        // The fixture is only verified, never executed. Reuse this compiled
        // test Mach-O so the regression requires no external app or identity.
        try files.copyItem(atPath: CommandLine.arguments[0], toPath: macOS.appendingPathComponent(executable).path)
        let signed = try process("/usr/bin/codesign", ["--force", "--sign", "-", "--timestamp=none",
                                                       "--options", "runtime", bundle.path])
        try check(signed.0 == 0, "Could not ad-hoc sign private requirement fixture: " + signed.1)
        #if arch(arm64)
        let architecture = "arm64"
        #elseif arch(x86_64)
        let architecture = "x86_64"
        #else
        #error("Unsupported installer test architecture")
        #endif
        let display = try process("/usr/bin/codesign", ["--display", "--verbose=4", "--architecture", architecture, bundle.path])
        let hashes = display.1.split(separator: "\n").filter { $0.hasPrefix("CDHash=") }
        try check(display.0 == 0 && hashes.count == 1, "Could not inspect fixture CDHash: " + display.1)
        let hash = String(hashes[0].dropFirst("CDHash=".count))
        try check(hash.count == 40 && hash.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }, "Invalid fixture CDHash")
        let base = "identifier \"\(identifier)\""
        let pin = "\(base) and cdhash H\"\(hash)\""
        let wrongBase = "identifier \"\(identifier).wrong\""
        let wrongHash = (hash.first == "0" ? "1" : "0") + hash.dropFirst()
        let cases: [(RunningBinding, [Int32])] = [
            (RunningBinding(baseRequirement: base, pinnedRequirement: pin, architecture: architecture), [0, 0]),
            (RunningBinding(baseRequirement: wrongBase, pinnedRequirement: "\(wrongBase) and cdhash H\"\(hash)\"", architecture: architecture), [3, 3]),
            (RunningBinding(baseRequirement: base, pinnedRequirement: "\(base) and cdhash H\"\(wrongHash)\"", architecture: architecture), [0, 3])
        ]
        for (binding, expected) in cases {
            let command = try stageCommand(source: root.path, uid: getuid(), binding: binding)
            let lines = command.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { $0.hasPrefix("/usr/bin/codesign ") }
            try check(lines.count == 2, "Expected exactly two generated codesign gates")
            for (index, line) in lines.enumerated() {
                // Execute the actual generated lines, not a reconstructed
                // equivalent. All privileged staging operations stay uncalled.
                let result = try process("/bin/zsh", ["-f", "-c", "package_stage=" + shellQuote(root.path) + "\n" + line])
                try check(result.0 == expected[index], "Generated codesign gate \(index) returned \(result.0), expected \(expected[index]): " + result.1)
            }
        }
    }
    static func testActualUserACL() throws {
        try check(geteuid() != 0, "ACL access regression must run without root privileges")
        let files = FileManager.default
        let root = URL(fileURLWithPath: "/private/tmp/keep-vault-installer-acl-" + UUID().uuidString)
        let directory = root.appendingPathComponent("restricted")
        let document = directory.appendingPathComponent("read-only.txt")
        let executable = directory.appendingPathComponent("executable")
        try files.createDirectory(at: root, withIntermediateDirectories: false)
        defer {
            _ = chmod(directory.path, 0o700)
            _ = chmod(document.path, 0o600)
            _ = chmod(executable.path, 0o700)
            try? files.removeItem(at: root)
        }
        try files.createDirectory(at: directory, withIntermediateDirectories: false)
        let payload = Data("private ACL fixture\n".utf8)
        try payload.write(to: document, options: .withoutOverwriting)
        try files.copyItem(atPath: "/usr/bin/true", toPath: executable.path)
        try check(chmod(document.path, 0) == 0 && chmod(executable.path, 0o100) == 0, "Could not restrict private ACL fixture")
        let unreadable = open(document.path, O_RDONLY)
        if unreadable >= 0 { close(unreadable) }
        try check(unreadable < 0, "Fixture was readable before adding its ACL")
        let binding = RunningBinding(baseRequirement: "unused", pinnedRequirement: "unused", architecture: "arm64")
        let command = try stageCommand(source: root.path, uid: getuid(), binding: binding)
        let lines = command.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { $0.hasPrefix("package_acl_") || $0.contains("$package_acl_user") ||
                ($0.hasPrefix("/usr/bin/find ") && $0.contains("/bin/chmod +a ")) }
        try check(lines.filter { $0.contains("/bin/chmod +a ") }.count == 3, "Expected exactly three generated ACL grants")
        try check(lines.filter { $0.contains("/usr/bin/id -u ") }.count == 2, "Expected both generated account-to-UID checks")
        let applied = try process("/bin/zsh", ["-f", "-c", "set -e\npackage_stage=" + shellQuote(root.path) + "\n" + lines.joined(separator: "\n")])
        try check(applied.0 == 0, "Actual generated ACL commands failed: " + applied.1)
        // Remove the owner's POSIX permissions after find has traversed the
        // fixture. Subsequent access must be provided by the generated ACLs.
        // macOS exec requires at least one POSIX execute bit. Setting only
        // others' execute bit leaves the owner without POSIX access, so this
        // process still needs the user ACL for both reading and executing.
        try check(chmod(directory.path, 0) == 0 && chmod(executable.path, 0o001) == 0, "Could not isolate ACL access")
        let contents = try Data(contentsOf: document)
        try check(contents == payload, "User ACL did not grant file read and directory search")
        let names = try files.contentsOfDirectory(atPath: directory.path)
        try check(names.contains("read-only.txt"), "User ACL did not grant directory listing")
        let write = open(document.path, O_WRONLY)
        if write >= 0 { close(write) }
        try check(write < 0, "Read-only ACL unexpectedly granted file write access")
        let create = open(directory.appendingPathComponent("must-not-be-created").path, O_WRONLY | O_CREAT | O_EXCL, 0o600)
        if create >= 0 { close(create) }
        try check(create < 0, "Read-only ACL unexpectedly granted directory write access")
        let executed = try process(executable.path, [])
        try check(executed.0 == 0, "User ACL did not grant executable access: " + executed.1)
        let removed = try process("/bin/chmod", ["-N", document.path])
        try check(removed.0 == 0, "Could not remove private ACL control")
        let deniedAgain = open(document.path, O_RDONLY)
        if deniedAgain >= 0 { close(deniedAgain) }
        try check(deniedAgain < 0, "Read unexpectedly succeeded after removing the ACL")
    }
    @MainActor static func testPresentation() throws {
        let application = NSApplication.shared
        application.setActivationPolicy(.prohibited)
        for english in [false, true] {
            let short = incompletePackageMessage(english: english)
            try check(short == (english
                ? "Extract the complete release ZIP into its own folder and keep every package file together. Then select that folder."
                : "Entpacke das vollständige Release-ZIP in einen eigenen Ordner und lasse alle Paketdateien zusammen. Wähle anschließend diesen Ordner aus."), "Incomplete package guidance is not localized")
            let shortCases: [(Bool, String)] = [
                (false, short), (true, english ? "Installation completed." : "Installation abgeschlossen."),
                (false, String(repeating: "a", count: 400)), (false, "1\n2\n3\n4\n5\n6")
            ]
            for (success, text) in shortCases {
                let alert = makeInstallerResultAlert(success: success, text: text, english: english)
                try check(alert.informativeText == text && alert.accessoryView == nil, "Short message was hidden or changed")
                try check(alert.alertStyle == (success ? .informational : .warning), "Alert style changed")
                try check(alert.messageText == (success
                    ? (english ? "Installation completed" : "Installation abgeschlossen")
                    : (english ? "Installation stopped" : "Installation angehalten")), "Alert title is not localized")
                try check(alert.buttons.count == 1 && alert.buttons[0].title == "OK", "Expected one clear OK button")
                alert.layout()
                try check(alert.window.frame.height <= 650 && alert.window.frame.width <= 850, "Short message grew beyond the screen-sized layout")
                try check(!alert.window.isVisible, "Short message test displayed a window")
            }
            let longCases = [
                "Installer exit 2.\n" + String(repeating: "Prüfung: Testdatei bestätigt.\n", count: 4_700) + "LETZTE ZEILE / LAST LINE",
                String(repeating: "x", count: 131_072),
                String(repeating: "a", count: 401),
                "1\n2\n3\n4\n5\n6\n7",
                String(repeating: "🔐", count: 201)
            ]
            for text in longCases {
                let alert = makeInstallerResultAlert(success: false, text: text, english: english)
                guard let scroll = alert.accessoryView as? NSScrollView,
                      let details = scroll.documentView as? NSTextView else {
                    throw InstallFailure(text: "Long details lack a scrollable text view")
                }
                try check(alert.informativeText == (english
                    ? "You can read, select and copy the details in the scrollable field below."
                    : "Die Details kannst du im scrollbaren Feld unten lesen, markieren und kopieren."), "Long alert guidance is not localized")
                try check(alert.informativeText.utf16.count < 150, "Long log escaped into the alert caption")
                try check(details.string == text, "Long details were truncated or modified")
                try check(!details.isEditable && details.isSelectable && !details.isRichText && !details.importsGraphics && !details.allowsUndo,
                          "Details must remain selectable plain text without editing")
                try check(scroll.frame.size == NSSize(width: 600, height: 240), "Details viewport is not bounded")
                try check(scroll.hasVerticalScroller && !scroll.hasHorizontalScroller, "Details cannot scroll vertically or require horizontal scrolling")
                try check(!details.isHorizontallyResizable && details.isVerticallyResizable && details.textContainer?.widthTracksTextView == true,
                          "Long lines do not wrap within the viewport")
                try check(details.font?.pointSize == 13, "Details font is not the readable system size")
                alert.layout()
                try check(scroll.frame.size == NSSize(width: 600, height: 240), "Alert layout expanded the details viewport")
                try check(alert.window.frame.height <= 650 && alert.window.frame.width <= 850, "Long alert grew beyond its bounded layout")
                if text.utf16.count > 10_000 {
                    try check(details.frame.height > scroll.contentSize.height, "Long content does not extend into the scrollable area")
                    let last = NSRange(location: (text as NSString).length - 1, length: 1)
                    details.setSelectedRange(last)
                    details.scrollRangeToVisible(last)
                    try check(details.selectedRange() == last, "Last detail character cannot be selected")
                    try check(scroll.contentView.bounds.minY > 0, "Last detail line cannot be scrolled into view")
                }
                try check(!alert.window.isVisible, "Presentation test displayed a window")
            }
        }
        try check(application.windows.allSatisfy { !$0.isVisible }, "Presentation test left a visible window")
    }
    @MainActor static func run() throws {
        let payloads = ["", "normal", "a b Ä Ü", "one'two", "$HOME $(printf PWNED) `printf PWNED`",
                        "'; printf PWNED; #", "back\\slash\"quotes", "line1\nline2\rline3\tend"]
        for payload in payloads {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/bin/zsh")
            process.arguments = ["-f", "-c", "print -rn -- " + shellQuote(payload)]
            process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
            let pipe = Pipe(); process.standardOutput = pipe; process.standardError = pipe
            try process.run()
            let actual = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            try check(process.terminationStatus == 0 && String(decoding: actual, as: UTF8.self) == payload, "Shell literal roundtrip failed for " + String(reflecting: payload) + ": " + String(reflecting: String(decoding: actual, as: UTF8.self)))
            guard let appleScript = NSAppleScript(source: "return " + appleScriptQuote(payload)) else {
                throw InstallFailure(text: "AppleScript literal did not compile")
            }
            var scriptError: NSDictionary?
            let value = appleScript.executeAndReturnError(&scriptError)
            try check(scriptError == nil && value.stringValue == payload, "AppleScript literal roundtrip failed")
        }
        let accepted = try parseStagedPackage("/private/tmp/keep-vault-package.aZ1902Bb\t7:12345")
        try check(accepted.root.hasSuffix("aZ1902Bb") && accepted.identity == "7:12345", "Valid staging output rejected")
        let invalid = ["", "/tmp/keep-vault-package.aZ1902Bb\t7:12345", "/private/tmp/keep-vault-package.\t7:12345",
                       "/private/tmp/keep-vault-package.aZ1902B/\t7:12345", "/private/tmp/keep-vault-package.aZ1902Bä\t7:12345",
                       "/private/tmp/keep-vault-package.aZ1902Bb\t7:", "/private/tmp/keep-vault-package.aZ1902Bb\t:12345",
                       "/private/tmp/keep-vault-package.aZ1902Bb\t7:12345:4", "/private/tmp/keep-vault-package.aZ1902Bb\t7:１２３",
                       "/private/tmp/keep-vault-package.aZ1902Bb\t7:12345\n", "/private/tmp/keep-vault-package.aZ1902Bb\t7:12345\textra"]
        for value in invalid {
            do { _ = try parseStagedPackage(value); throw InstallFailure(text: "Invalid staging output accepted: " + value) }
            catch let failure as InstallFailure {
                try check(failure.text == "The authenticated staging result was invalid. No application was installed.", failure.text)
            }
        }
        try check(packageNames.count == 20 && Set(packageNames).count == 20, "Fixed package allowlist drifted")
        let binding = RunningBinding(baseRequirement: "BASE_REQUIREMENT", pinnedRequirement: "DYNAMIC_PIN", architecture: "arm64")
        let command = try stageCommand(source: "/private/tmp/a' b $HOME ; `touch bad` Ä", uid: getuid(), binding: binding)
        let syntax = Process(); syntax.executableURL = URL(fileURLWithPath: "/bin/zsh")
        syntax.arguments = ["-fn", "-c", command]
        syntax.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        try syntax.run(); syntax.waitUntilExit()
        try check(syntax.terminationStatus == 0, "Generated administrative block is not valid zsh")
        try testActualCodesignRequirements()
        try testActualUserACL()
        try testPresentation()
        let native = command.range(of: "\"$package_stage/package/Keep Vault Installer.app/Contents/MacOS/Keep Vault Release Verifier\"")!
        for gate in ["/bin/chmod -N", "/usr/bin/ditto --noacl", "package_unsafe=", "/usr/sbin/chown -R -P 0:0",
                     "package_foreign_owner=", "--all-architectures -R", "--architecture 'arm64'", "/usr/bin/syspolicy_check distribution"] {
            try check(command.range(of: gate)!.lowerBound < native.lowerBound, "Native executed before " + gate)
        }
        print("installer_entry_helpers=passed; shell_literals=8; applescript_literals=8; staged_output=12; package_allowlist=20; bootstrap_order=8; real_codesign_requirements=6; real_user_acl=passed; presentation_cases=18; presentation_languages=2; visible_windows=0")
    }
}
'''
with tempfile.TemporaryDirectory(prefix="keep-vault-installer-entry-tests-", dir="/private/tmp") as temporary:
    folder = Path(temporary)
    swift = folder / "HelperTests.swift"
    swift.write_text(helpers + harness)
    binary = folder / "HelperTests"
    subprocess.run(["/usr/bin/xcrun", "swiftc", "-parse-as-library", "-warnings-as-errors",
                    "-O", "-target", "arm64-apple-macos14.0", str(swift), "-o", str(binary)], check=True)
    subprocess.run([str(binary)] + (["--presentation-only"] if arguments.presentation_only else []), check=True)
