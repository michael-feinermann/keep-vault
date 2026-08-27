import AppKit
import Darwin
import Foundation

/// LaunchServices enforces `LSMultipleInstancesProhibited` for Finder and
/// `open -n`. A user can still execute the signed Mach-O directly, which
/// bypasses LaunchServices, so the process also holds a non-blocking advisory
/// lock in its sandbox container until process exit. The live application
/// registry is used only to bring the winner forward, never as the exclusion
/// primitive: two simultaneous direct starts may not be registry-visible to
/// one another yet, while `flock` resolves that race atomically in the kernel.
enum SingleInstancePolicy {
    static let bundleIdentifier = "de.michael-feinermann.qr-scanner"
    @MainActor private static var heldLease: SingleInstanceLease?

    static func shouldContinue(currentPID: pid_t, runningPIDs: [pid_t]) -> Bool {
        let winner = (runningPIDs + [currentPID])
            .filter { $0 > 0 }
            .min()
        return winner == currentPID
    }

    @MainActor
    static func claimOrActivateExisting() -> Bool {
        guard Bundle.main.bundleIdentifier == bundleIdentifier else {
            // A production executable whose embedded metadata no longer names
            // the reviewed bundle cannot safely make a single-instance claim.
            return false
        }

        if heldLease != nil { return true }

        let lockURL: URL
        do {
            let support = try FileManager.default.url(
                for: .applicationSupportDirectory,
                in: .userDomainMask,
                appropriateFor: nil,
                create: true)
            lockURL = support.appendingPathComponent(".qr-scanner.instance.lock", isDirectory: false)
        } catch {
            return false
        }

        let lease: SingleInstanceLease?
        do {
            lease = try acquireLock(at: lockURL.path)
        } catch {
            return false
        }

        let running = NSRunningApplication
            .runningApplications(withBundleIdentifier: bundleIdentifier)
            .filter { !$0.isTerminated }
        guard let lease else {
            running
                .min { $0.processIdentifier < $1.processIdentifier }?
                .activate(options: [.activateAllWindows])
            return false
        }

        let currentPID = ProcessInfo.processInfo.processIdentifier
        let runningPIDs = running.map(\.processIdentifier)
        guard shouldContinue(currentPID: currentPID, runningPIDs: runningPIDs) else {
            running
                .filter { $0.processIdentifier != currentPID }
                .min { $0.processIdentifier < $1.processIdentifier }?
                .activate(options: [.activateAllWindows])
            return false
        }

        heldLease = lease
        return true
    }

    static func acquireLock(at path: String) throws -> SingleInstanceLease? {
        let descriptor = path.withCString { pointer in
            Darwin.open(
                pointer,
                O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC,
                mode_t(S_IRUSR | S_IWUSR))
        }
        guard descriptor >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }

        var keepDescriptor = false
        defer {
            if !keepDescriptor { Darwin.close(descriptor) }
        }

        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        guard (metadata.st_mode & S_IFMT) == S_IFREG,
              metadata.st_uid == geteuid(),
              metadata.st_nlink == 1 else {
            throw POSIXError(.EPERM)
        }
        guard fchmod(descriptor, mode_t(S_IRUSR | S_IWUSR)) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }

        if flock(descriptor, LOCK_EX | LOCK_NB) != 0 {
            if errno == EWOULDBLOCK || errno == EAGAIN {
                return nil
            }
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }

        // Hold the exact opened object, not merely the pathname. A pathname
        // that changed between open and this check cannot become the app's
        // exclusion token.
        var pathMetadata = stat()
        guard path.withCString({ lstat($0, &pathMetadata) }) == 0,
              pathMetadata.st_dev == metadata.st_dev,
              pathMetadata.st_ino == metadata.st_ino else {
            _ = flock(descriptor, LOCK_UN)
            throw POSIXError(.ESTALE)
        }

        keepDescriptor = true
        return SingleInstanceLease(descriptor: descriptor)
    }
}

final class SingleInstanceLease {
    private var descriptor: Int32

    fileprivate init(descriptor: Int32) {
        self.descriptor = descriptor
    }

    deinit {
        if descriptor >= 0 {
            _ = flock(descriptor, LOCK_UN)
            _ = Darwin.close(descriptor)
            descriptor = -1
        }
    }
}
