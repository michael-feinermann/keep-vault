using System.Globalization;
using Avalonia.Controls;
using Avalonia.Threading;
using KalynaArchiver.Services;

namespace KalynaArchiver;

public sealed partial class MainWindow
{
    private OperationProgressTracker? _operationProgress;
    private IDisposable? _operationProgressScope;
    private DispatcherTimer? _operationProgressTimer;
    private bool _operationReportedSuccess;
    private bool _operationReportedFailure;
    private long _lastAnnouncedPhase = -1;

    private void BeginOperationProgress()
    {
        _operationReportedSuccess = _operationReportedFailure = false;
        _lastAnnouncedPhase = -1;
        try
        {
            DisposeProgressObserver();
            _operationProgress = new OperationProgressTracker();
            _operationProgressScope = _operationProgress.EnterScope();
            _operationProgress.BeginPhase(OperationPhase.Inventory, ProgressUnit.Files)?.Dispose();
            OperationProgressPanel.IsVisible = true;
            _operationProgressTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
            _operationProgressTimer.Tick += OnOperationProgressTick;
            _operationProgressTimer.Start();
            RenderOperationProgress();
        }
        catch { DisposeProgressObserver(); ShowProgressUnavailable(); }
    }

    private void OnOperationProgressTick(object? sender, EventArgs e)
    {
        try { if (WindowState != WindowState.Minimized && IsVisible) RenderOperationProgress(); }
        catch { ShowProgressUnavailable(); }
    }

    private void MarkOperationSucceeded() => _operationReportedSuccess = true;
    private void MarkOperationFailed()
    {
        _operationReportedFailure = true;
        try { _operationProgress?.SetState(OperationToken.IsCancellationRequested
            ? OperationProgressState.Cancelling : OperationProgressState.Failed); }
        catch { ShowProgressUnavailable(); }
    }

    private void FinishOperationProgress(bool cancelled)
    {
        try
        {
            if (_operationProgress is { } tracker)
            {
                if (_operationReportedFailure) tracker.SetState(cancelled ? OperationProgressState.Cancelled : OperationProgressState.Failed);
                else if (cancelled || !_operationReportedSuccess) tracker.SetState(OperationProgressState.Cancelled);
                else tracker.Complete();
                RenderOperationProgress();
            }
        }
        catch { ShowProgressUnavailable(); }
        finally { DisposeProgressObserver(); }
    }

    private void DisposeProgressObserver()
    {
        DispatcherTimer? timer = _operationProgressTimer;
        _operationProgressTimer = null;
        // Each cleanup is independent: a UI failure cannot skip scope restoration.
        try { if (timer is not null) timer.Tick -= OnOperationProgressTick; } catch { }
        try { timer?.Stop(); } catch { }
        try { _operationProgress?.Dispose(); } catch { }
        IDisposable? scope = _operationProgressScope;
        _operationProgressScope = null;
        try { scope?.Dispose(); } catch { }
    }

    private void ShowProgressUnavailable()
    {
        try { OperationProgressDetailsText.Text = IsEnglish ? "Progress display unavailable." : "Fortschrittsanzeige derzeit nicht verfügbar."; }
        catch { /* Cosmetic fallback has no operation or cleanup authority. */ }
    }

    private void RenderOperationProgress()
    {
        if (_disposed || _operationProgress is null) return;
        try
        {
            OperationProgressSnapshot snapshot = _operationProgress.Snapshot();
            string phase = ProgressPhaseText(snapshot.Phase);
            string state = snapshot.State switch
            {
                OperationProgressState.Completed => IsEnglish ? "Completed" : "Abgeschlossen",
                OperationProgressState.Cancelled => IsEnglish ? "Cancelled" : "Abgebrochen",
                OperationProgressState.Cancelling => IsEnglish ? "Completing cancellation" : "Abbruch wird abgeschlossen",
                OperationProgressState.Failed => IsEnglish ? "Failed" : "Fehlgeschlagen",
                OperationProgressState.WaitingForResource => IsEnglish ? "Waiting for resources" : "Wartet auf Ressourcen",
                OperationProgressState.AwaitingUser => IsEnglish ? "Waiting for your decision" : "Wartet auf deine Entscheidung",
                _ => (IsEnglish ? "Phase: " : "Phase: ") + phase,
            };
            OperationPhaseText.Text = state;
            bool completed = snapshot.State == OperationProgressState.Completed;
            bool terminal = snapshot.State is OperationProgressState.Completed or OperationProgressState.Cancelled or OperationProgressState.Failed;
            bool measured = snapshot.TotalUnits is > 0;
            OperationPhaseProgress.IsIndeterminate = !terminal && !measured;
            OperationPhaseProgress.Value = completed ? 100 : measured
                ? (double)snapshot.CompletedUnits / snapshot.TotalUnits!.Value * 100 : 0;
            string count = FormatProgressCount(snapshot.CompletedUnits, snapshot.Unit);
            if (snapshot.TotalUnits is long total) count += (IsEnglish ? " of " : " von ") + FormatProgressCount(total, snapshot.Unit);
            string elapsed = FormatDuration(snapshot.ElapsedDuration, approximate: false);
            string eta = snapshot.PhaseRemaining is TimeSpan remaining ? FormatDuration(remaining, approximate: true)
                : IsEnglish ? "not currently estimable" : "derzeit nicht schätzbar";
            string details = terminal ? (IsEnglish ? "Elapsed: " : "Verstrichen: ") + elapsed
                : (IsEnglish ? "Processed: " : "Verarbeitet: ") + count
                    + " · " + (IsEnglish ? "Phase remaining: " : "Restzeit dieser Phase: ") + eta
                    + " · " + (IsEnglish ? "Overall remaining: unknown" : "Gesamtrestzeit: unbekannt")
                    + " · " + (IsEnglish ? "Elapsed: " : "Verstrichen: ") + elapsed;
            if (!terminal && snapshot.RatePerSecond is double rate)
                details += " · " + FormatProgressCount((long)Math.Min(rate, long.MaxValue), snapshot.Unit) + "/s";
            if (snapshot.PausedDuration > TimeSpan.Zero)
                details += " · " + (IsEnglish ? "Paused: " : "Pausiert: ") + FormatDuration(snapshot.PausedDuration, false);
            OperationProgressDetailsText.Text = details;
            // The text is not a live region: no four-times-per-second announcements.
            if (_lastAnnouncedPhase != snapshot.PhaseId || terminal)
            {
                Avalonia.Automation.AutomationProperties.SetName(OperationPhaseProgress, state);
                _lastAnnouncedPhase = snapshot.PhaseId;
            }
        }
        catch
        {
            // A presentation failure must not propagate to crypto, cleanup or cancellation.
            ShowProgressUnavailable();
        }
    }

    private string ProgressPhaseText(OperationPhase phase) => (phase, IsEnglish) switch
    {
        (OperationPhase.Inventory, true) => "Inventory", (OperationPhase.Inventory, false) => "Inventarisierung",
        (OperationPhase.Entropy, true) => "Pool preparation", (OperationPhase.Entropy, false) => "Poolvorbereitung",
        (OperationPhase.KeyDerivation, true) => "Key derivation", (OperationPhase.KeyDerivation, false) => "Schlüsselableitung",
        (OperationPhase.GlobalVerification, true) => "Reading and integrity verification", (OperationPhase.GlobalVerification, false) => "Lesen und Integritätsprüfung",
        (OperationPhase.Compression, true) => "Compression", (OperationPhase.Compression, false) => "Kompression",
        (OperationPhase.Encryption, true) => "Encryption and writing", (OperationPhase.Encryption, false) => "Verschlüsseln und Schreiben",
        (OperationPhase.Extraction, true) => "Decryption and extraction", (OperationPhase.Extraction, false) => "Entschlüsselung und Extraktion",
        (OperationPhase.Recovery, true) => "Recovery", (OperationPhase.Recovery, false) => "Recovery",
        (OperationPhase.ResultVerification, true) => "Result verification", (OperationPhase.ResultVerification, false) => "Ergebnisprüfung",
        (OperationPhase.Commit, true) => "Committing result", (OperationPhase.Commit, false) => "Ergebnis freigeben",
        (OperationPhase.Cleanup, true) => "Cleanup", _ => "Bereinigung",
    };

    private string FormatProgressCount(long value, ProgressUnit unit)
    {
        if (unit == ProgressUnit.Bytes)
        {
            if (value >= 1L << 40) return ((double)value / (1L << 40)).ToString("0.##", CultureInfo.CurrentCulture) + " TiB";
            if (value >= 1L << 30) return ((double)value / (1L << 30)).ToString("0.##", CultureInfo.CurrentCulture) + " GiB";
            if (value >= 1L << 20) return ((double)value / (1L << 20)).ToString("0.##", CultureInfo.CurrentCulture) + " MiB";
            if (value >= 1024) return ((double)value / 1024).ToString("0.##", CultureInfo.CurrentCulture) + " KiB";
            return value.ToString(CultureInfo.CurrentCulture) + " B";
        }
        string label = unit switch
        {
            ProgressUnit.Files => IsEnglish ? "entries" : "Einträge",
            ProgressUnit.Records => IsEnglish ? "records" : "Records",
            ProgressUnit.Stripes => "Stripes",
            _ => IsEnglish ? "steps" : "Schritte",
        };
        return value.ToString(CultureInfo.CurrentCulture) + " " + label;
    }

    private string FormatDuration(TimeSpan value, bool approximate)
    {
        string prefix = approximate ? IsEnglish ? "approximately " : "ca. " : string.Empty;
        if (value.TotalMinutes < 1) return prefix + (IsEnglish ? "less than 1 min" : "weniger als 1 min");
        if (value.TotalHours < 1) return prefix + Math.Ceiling(value.TotalMinutes).ToString(CultureInfo.CurrentCulture) + " min";
        if (value.TotalDays < 1) return prefix + value.TotalHours.ToString("0.0", CultureInfo.CurrentCulture) + " h";
        return prefix + value.TotalDays.ToString("0.0", CultureInfo.CurrentCulture) + (IsEnglish ? " days" : " Tage");
    }
}
