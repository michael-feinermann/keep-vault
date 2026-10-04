using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Platform.Storage;
using Avalonia.Threading;

namespace KalynaArchiver;

public sealed partial class App : Application
{
    private MainWindow? _mainWindow;
    private IActivatableLifetime? _activatableLifetime;
    private readonly List<IStorageItem> _pendingActivationItems = [];
    private readonly HashSet<IStorageItem> _disposingActivationItems = new(ReferenceEqualityComparer.Instance);
    private readonly List<MainWindow> _activationStorageWindows = [];
    private Exception? _lastActivationFailure;
    internal Exception? LastFileActivationFailure => _lastActivationFailure;

    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            _mainWindow = new MainWindow();
            desktop.MainWindow = _mainWindow;
            desktop.Exit += Desktop_Exit;
        }

        if (ApplicationLifetime is IActivatableLifetime activatableLifetime)
        {
            _activatableLifetime = activatableLifetime;
            activatableLifetime.Activated += ActivatableLifetime_Activated;
        }

        base.OnFrameworkInitializationCompleted();
    }

    private void ActivatableLifetime_Activated(object? sender, ActivatedEventArgs e)
    {
        if (e is not FileActivatedEventArgs fileActivation)
        {
            return;
        }

        IStorageItem[] items = fileActivation.Files.ToArray();
        if (Dispatcher.UIThread.CheckAccess())
        {
            ProcessFileActivation(items);
        }
        else
        {
            Dispatcher.UIThread.Post(() => ProcessFileActivation(items));
        }
    }

    private void ProcessFileActivation(IReadOnlyList<IStorageItem> items)
    {
        try { ActivateFirstArchive(items); }
        catch (Exception failure)
        {
            _lastActivationFailure = failure;
            if (_mainWindow is { } window) _ = window.ReportFileActivationFailureAsync(failure);
        }
    }

    private void ActivateFirstArchive(IReadOnlyList<IStorageItem> items)
    {
        bool accepted = false;
        List<Exception>? failures = null;
        var seen = new HashSet<IStorageItem>(ReferenceEqualityComparer.Instance);
        foreach (IStorageItem item in items)
        {
            if (!seen.Add(item)) continue;
            MainWindow? window = _mainWindow;
            bool consumed = false;
            try
            {
                if (_pendingActivationItems.Any(owner => ReferenceEquals(owner, item)) || _disposingActivationItems.Contains(item))
                {
                    consumed = true;
                    throw new ObjectDisposedException(nameof(IStorageItem), "Activation item cleanup must complete before reuse.");
                }
                if (!accepted && item is IStorageFile file && window is not null)
                    accepted = window.HandleFileActivation(file, out consumed);
            }
            catch (Exception failure) { (failures ??= []).Add(failure); }
            finally
            {
                if (!consumed)
                {
                    try { DisposeActivationItem(item, window); }
                    catch (Exception failure) { (failures ??= []).Add(failure); }
                }
                if (window is not null) TrackActivationWindow(window);
            }
        }
        if (failures is not null) throw new AggregateException("File activation ownership update failed.", failures);
    }

    private void TrackActivationWindow(MainWindow window)
    {
        if (window.HasActivationStorageOwnership)
        {
            if (!_activationStorageWindows.Contains(window)) _activationStorageWindows.Add(window);
        }
        else _activationStorageWindows.Remove(window);
    }

    private void DisposeActivationItem(IStorageItem item, MainWindow? window)
    {
        MainWindow? owner = _activationStorageWindows.FirstOrDefault(candidate => candidate.OwnsActivationStorageItem(item));
        if (owner is not null) return; // A live or terminal window owner already owns this reference.
        if (window is not null)
        {
            if (!_disposingActivationItems.Add(item)) return;
            try { window.DisposeUnacceptedActivationItem(item); }
            finally { _disposingActivationItems.Remove(item); }
            return;
        }
        DisposeRawActivationItem(item);
    }

    private void DisposeRawActivationItem(IStorageItem item)
    {
        if (!_disposingActivationItems.Add(item)) return;
        try
        {
            item.Dispose();
            _pendingActivationItems.RemoveAll(owner => ReferenceEquals(owner, item));
        }
        catch
        {
            if (!_pendingActivationItems.Any(owner => ReferenceEquals(owner, item))) _pendingActivationItems.Add(item);
            throw;
        }
        finally { _disposingActivationItems.Remove(item); }
    }

    internal void RetryActivationStorageCleanup()
    {
        List<Exception>? failures = null;
        foreach (MainWindow window in _activationStorageWindows.ToArray())
        {
            try { window.RetryActivationStorageCleanup(); }
            catch (Exception failure) { (failures ??= []).Add(failure); }
            finally { TrackActivationWindow(window); }
        }
        foreach (IStorageItem item in _pendingActivationItems.ToArray())
        {
            try { DisposeRawActivationItem(item); }
            catch (Exception failure) { (failures ??= []).Add(failure); }
        }
        if (failures is not null) throw new AggregateException("Application activation cleanup failed.", failures);
    }

    private void Desktop_Exit(object? sender, ControlledApplicationLifetimeExitEventArgs e)
    {
        if (_activatableLifetime is not null)
        {
            _activatableLifetime.Activated -= ActivatableLifetime_Activated;
            _activatableLifetime = null;
        }

        if (_mainWindow is { } window) TrackActivationWindow(window);
        _mainWindow = null;
        try { RetryActivationStorageCleanup(); }
        catch (Exception failure) { _lastActivationFailure = failure; }
    }
}
