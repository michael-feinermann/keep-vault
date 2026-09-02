import Foundation

/// The delivery state shared by the real camera session and its lifecycle
/// regression test. Frames may be decoded off the main queue, but they are
/// delivered only while this state says the current scan is active.
struct ScanSessionLifecycle {
    private enum State {
        case suspended
        case active
        case stopped
    }

    private var state: State = .suspended

    var acceptsDetections: Bool {
        state == .active
    }

    var canResume: Bool {
        state != .stopped
    }

    @discardableResult
    mutating func resume() -> Bool {
        guard state != .stopped else { return false }
        state = .active
        return true
    }

    mutating func suspend() {
        guard state != .stopped else { return }
        state = .suspended
    }

    mutating func stop() {
        state = .stopped
    }
}

/// Thread-safe terminal flag for work already queued off the main actor.
/// `ScanSessionLifecycle` remains the main-actor policy; this companion gate
/// prevents a delayed `startRunning()` block from reopening the camera after
/// the window-close path made stop terminal.
final class ScanSessionTerminationGate: @unchecked Sendable {
    private let lock = NSLock()
    private var stopped = false

    var isStopped: Bool {
        lock.lock()
        defer { lock.unlock() }
        return stopped
    }

    func stop() {
        lock.lock()
        stopped = true
        lock.unlock()
    }
}

/// Main-actor gate shared by the window-close and application-termination
/// paths. AppKit may deliver both for the same user action (closing the last
/// window calls terminate, which then emits applicationWillTerminate), so the
/// cleanup body must run exactly once.
@MainActor
final class IdempotentTerminationCleanup {
    private var completed = false

    func run(_ cleanup: () -> Void) {
        guard !completed else { return }
        completed = true
        cleanup()
    }
}
