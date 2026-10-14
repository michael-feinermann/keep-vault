using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Controls.Presenters;
using Avalonia.Controls.Primitives;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;
using Avalonia.VisualTree;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace KalynaArchiver;

public sealed partial class MainWindow
{
    private const int ConsoleVisibleLines = 12;
    private readonly object _consoleQueueGate = new();
    private readonly Queue<string> _consolePendingEntries = new();
    private int _consolePendingCharacters;
    private bool _consolePendingPruned;
    private bool _consoleHistoryPruned;
    private bool _consoleFollowOnExpansion;
    private bool _consoleObserverUnavailable;
    private DispatcherTimer? _consoleFlushTimer;
    private ScrollViewer? _consoleScrollViewer;
    private TextPresenter? _consoleTextPresenter;
    private long _consoleUpdateVersion;
    private long _consoleInteractionVersion;
    private double _consoleMeasuredFontSize = double.NaN;
    private double _consoleMeasuredScaling = double.NaN;
    private FontFamily? _consoleMeasuredFontFamily;
    private FontStyle _consoleMeasuredFontStyle;
    private FontWeight _consoleMeasuredFontWeight;
    private const int MainViewportButtonRows = 3;
    private double _consoleWorkspaceViewportHeight = double.NaN;
    private bool _consoleWorkspaceNeedsReveal;
    private bool _consoleWorkspaceRevealPending;
    private long _consoleWorkspaceInteractionVersion;

    private void InitializeConsole()
    {
        ConsoleExpander.PropertyChanged += ConsoleExpander_PropertyChanged;
        LogBox.LayoutUpdated += ConsoleLayoutUpdated;
        MainWorkspaceScrollViewer.LayoutUpdated += MainWorkspaceLayoutUpdated;
        MainWorkspaceScrollViewer.AddHandler(InputElement.PointerWheelChangedEvent, WorkspacePointerWheel, RoutingStrategies.Tunnel);
        MainWorkspaceScrollViewer.AddHandler(InputElement.PointerPressedEvent, WorkspacePointerPressed, RoutingStrategies.Tunnel);
        MainWorkspaceScrollViewer.AddHandler(InputElement.PointerMovedEvent, WorkspacePointerMoved, RoutingStrategies.Tunnel);
        MainWorkspaceScrollViewer.AddHandler(InputElement.KeyDownEvent, WorkspaceKeyDown, RoutingStrategies.Tunnel);
        MainTabs.SelectionChanged += MainWorkspaceTabChanged;
        LogBox.AddHandler(InputElement.PointerWheelChangedEvent, ConsolePointerWheel, RoutingStrategies.Tunnel);
        LogBox.AddHandler(InputElement.PointerPressedEvent, ConsolePointerPressed, RoutingStrategies.Tunnel);
        LogBox.AddHandler(InputElement.PointerMovedEvent, ConsolePointerMoved, RoutingStrategies.Tunnel);
        LogBox.AddHandler(InputElement.KeyDownEvent, ConsoleKeyDown, RoutingStrategies.Tunnel);
        // A single UI observer batches messages. Both the retained history and
        // messages waiting for this observer have independent finite bounds.
        _consoleFlushTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(100) };
        _consoleFlushTimer.Tick += ConsoleFlushTimer_Tick;
        _consoleFlushTimer.Start();
    }

    private void DisposeConsole()
    {
        _consoleFlushTimer?.Stop();
        if (_consoleFlushTimer is { } timer) timer.Tick -= ConsoleFlushTimer_Tick;
        _consoleFlushTimer = null;
        ConsoleExpander.PropertyChanged -= ConsoleExpander_PropertyChanged;
        LogBox.LayoutUpdated -= ConsoleLayoutUpdated;
        MainWorkspaceScrollViewer.LayoutUpdated -= MainWorkspaceLayoutUpdated;
        MainWorkspaceScrollViewer.RemoveHandler(InputElement.PointerWheelChangedEvent, WorkspacePointerWheel);
        MainWorkspaceScrollViewer.RemoveHandler(InputElement.PointerPressedEvent, WorkspacePointerPressed);
        MainWorkspaceScrollViewer.RemoveHandler(InputElement.PointerMovedEvent, WorkspacePointerMoved);
        MainWorkspaceScrollViewer.RemoveHandler(InputElement.KeyDownEvent, WorkspaceKeyDown);
        MainTabs.SelectionChanged -= MainWorkspaceTabChanged;
        LogBox.RemoveHandler(InputElement.PointerWheelChangedEvent, ConsolePointerWheel);
        LogBox.RemoveHandler(InputElement.PointerPressedEvent, ConsolePointerPressed);
        LogBox.RemoveHandler(InputElement.PointerMovedEvent, ConsolePointerMoved);
        LogBox.RemoveHandler(InputElement.KeyDownEvent, ConsoleKeyDown);
        lock (_consoleQueueGate)
        {
            _consolePendingEntries.Clear();
            _consolePendingCharacters = 0;
            _consolePendingPruned = false;
        }
        ++_consoleUpdateVersion;
    }

    private void ConsolePointerWheel(object? sender, PointerWheelEventArgs e) => ++_consoleInteractionVersion;
    private void ConsolePointerPressed(object? sender, PointerPressedEventArgs e) => ++_consoleInteractionVersion;
    private void ConsolePointerMoved(object? sender, PointerEventArgs e)
    {
        // A held thumb or selection drag can continue after an append captured
        // its offset. Ordinary hover must not cancel following new output.
        PointerPointProperties properties = e.GetCurrentPoint(LogBox).Properties;
        if (properties.IsLeftButtonPressed || properties.IsRightButtonPressed || properties.IsMiddleButtonPressed)
            ++_consoleInteractionVersion;
    }
    private void ConsoleKeyDown(object? sender, KeyEventArgs e) => ++_consoleInteractionVersion;

    private void WorkspacePointerWheel(object? sender, PointerWheelEventArgs e) => ++_consoleWorkspaceInteractionVersion;
    private void WorkspacePointerPressed(object? sender, PointerPressedEventArgs e) => ++_consoleWorkspaceInteractionVersion;
    private void WorkspacePointerMoved(object? sender, PointerEventArgs e)
    {
        PointerPointProperties properties = e.GetCurrentPoint(MainWorkspaceScrollViewer).Properties;
        if (properties.IsLeftButtonPressed || properties.IsRightButtonPressed || properties.IsMiddleButtonPressed)
            ++_consoleWorkspaceInteractionVersion;
    }
    private void WorkspaceKeyDown(object? sender, KeyEventArgs e) => ++_consoleWorkspaceInteractionVersion;

    private void MainWorkspaceTabChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (ReferenceEquals(e.Source, MainTabs) && ConsoleExpander.IsExpanded) _consoleWorkspaceNeedsReveal = true;
    }

    private void MainWorkspaceLayoutUpdated(object? sender, EventArgs e)
    {
        try { MeasureMainWorkspace(); }
        catch { ShowConsoleUnavailable(); }
    }

    private void MeasureMainWorkspace()
    {
        if (_disposed || MainTabs.SelectedContent is not Border panel || panel.Child is not ScrollViewer main) return;
        double workspaceHeight = MainWorkspaceScrollViewer.Viewport.Height;
        double buttonHeight = Math.Max(CancelOperationButton.Bounds.Height, CancelOperationButton.DesiredSize.Height);
        if (!double.IsFinite(workspaceHeight) || workspaceHeight <= 0 || !double.IsFinite(buttonHeight) || buttonHeight <= 0) return;
        if (workspaceHeight != _consoleWorkspaceViewportHeight)
        {
            _consoleWorkspaceViewportHeight = workspaceHeight;
            _consoleWorkspaceNeedsReveal |= ConsoleExpander.IsExpanded;
        }

        // Keep three actually measured action rows in the selected inner
        // viewport. Header and tab content may then scroll as one upper area;
        // neither is allowed to collapse the main viewport to zero.
        double minimumMainViewport = MainViewportButtonRows * buttonHeight;
        double topChrome = main.TranslatePoint(default, MainTabs)?.Y ?? 0;
        double bottomChrome = panel.Padding.Bottom + panel.BorderThickness.Bottom + panel.Margin.Bottom + MainTabs.Padding.Bottom;
        double minimumTabsHeight = minimumMainViewport + Math.Max(0, topChrome) + bottomChrome;
        double availableTabsHeight = workspaceHeight - HeaderCard.Bounds.Height - MainTabs.Margin.Top - MainTabs.Margin.Bottom;
        double tabsHeight = Math.Max(minimumTabsHeight, availableTabsHeight);
        if (!double.IsFinite(tabsHeight)) return;
        if (!double.IsFinite(MainTabs.Height) || Math.Abs(MainTabs.Height - tabsHeight) > 0.01)
        {
            _consoleWorkspaceNeedsReveal |= ConsoleExpander.IsExpanded;
            MainTabs.Height = tabsHeight;
            return;
        }

        if (!_consoleWorkspaceNeedsReveal || _consoleWorkspaceRevealPending || main.Viewport.Height + 0.01 < minimumMainViewport) return;
        _consoleWorkspaceRevealPending = true;
        long interactionVersion = _consoleWorkspaceInteractionVersion;
        Dispatcher.UIThread.Post(() =>
        {
            _consoleWorkspaceRevealPending = false;
            if (_disposed || interactionVersion != _consoleWorkspaceInteractionVersion)
            {
                _consoleWorkspaceNeedsReveal = false;
                return;
            }
            TryRestoreConsoleView(() =>
            {
                if (MainTabs.SelectedContent is not Border currentPanel || currentPanel.Child is not ScrollViewer currentMain) return;
                double viewport = MainWorkspaceScrollViewer.Viewport.Height;
                double currentButtonHeight = Math.Max(CancelOperationButton.Bounds.Height, CancelOperationButton.DesiredSize.Height);
                double currentMinimum = MainViewportButtonRows * currentButtonHeight;
                // A newer font or chrome reflow can arrive before this post.
                // Wait for its actual inner viewport instead of clearing its
                // reveal request using an older measured button height.
                if (!double.IsFinite(currentMinimum) || currentMinimum <= 0 || currentMain.Viewport.Height + 0.01 < currentMinimum) return;
                _consoleWorkspaceNeedsReveal = false;
                double mainTop = currentMain.TranslatePoint(default, MainWorkspaceScrollViewer)?.Y ?? 0;
                double visible = Math.Max(0, Math.Min(viewport, mainTop + currentMain.Bounds.Height) - Math.Max(0, mainTop));
                double required = Math.Min(currentMinimum, viewport);
                if (visible + 0.01 < required)
                    MainWorkspaceScrollViewer.Offset = new Vector(MainWorkspaceScrollViewer.Offset.X,
                        Math.Max(0, MainWorkspaceScrollViewer.Offset.Y + mainTop));
            });
        }, DispatcherPriority.Loaded);
    }

    private void ConsoleExpander_PropertyChanged(object? sender, AvaloniaPropertyChangedEventArgs e)
    {
        if (e.Property == Expander.IsExpandedProperty)
        {
            _consoleWorkspaceNeedsReveal |= ConsoleExpander.IsExpanded;
            try
            {
                ApplyConsoleLanguage();
                MeasureConsoleLines();
            }
            catch { ShowConsoleUnavailable(); }
            if (ConsoleExpander.IsExpanded && _consoleFollowOnExpansion)
            {
                _consoleFollowOnExpansion = false;
                long interactionVersion = _consoleInteractionVersion;
                Dispatcher.UIThread.Post(() =>
                {
                    if (!_disposed && ConsoleExpander.IsExpanded && interactionVersion == _consoleInteractionVersion &&
                        LogBox.SelectionStart == LogBox.SelectionEnd) TryRestoreConsoleView(() =>
                        {
                            if (_consoleScrollViewer is { } scroller) FollowConsoleVerticalEnd(scroller);
                        });
                }, DispatcherPriority.Loaded);
            }
        }
    }

    private void ApplyConsoleLanguage()
    {
        ConsoleToggleText.Text = T(ConsoleExpander.IsExpanded ? "consoleHide" : "consoleShow");
        ConsoleEndButton.Content = T("consoleEnd");
        ConsoleRetentionText.Text = _consoleObserverUnavailable ? T("consoleUnavailable") : _consoleHistoryPruned ? T("consolePruned") : string.Empty;
        AutomationProperties.SetName(ConsoleExpander, ConsoleToggleText.Text);
        AutomationProperties.SetName(LogBox, T("securityLog"));
        AutomationProperties.SetHelpText(LogBox, T("consoleEnd"));
    }

    private void ConsoleLayoutUpdated(object? sender, EventArgs e)
    {
        try
        {
            _consoleScrollViewer ??= LogBox.GetVisualDescendants().OfType<ScrollViewer>().FirstOrDefault();
            _consoleTextPresenter ??= LogBox.GetVisualDescendants().OfType<TextPresenter>().FirstOrDefault();
            MeasureConsoleLines();
        }
        catch { ShowConsoleUnavailable(); }
    }

    private void MeasureConsoleLines()
    {
        double scaling = TopLevel.GetTopLevel(this)?.RenderScaling ?? 1;
        bool fontChanged = _consoleMeasuredFontSize != LogBox.FontSize || _consoleMeasuredScaling != scaling ||
            !Equals(_consoleMeasuredFontFamily, LogBox.FontFamily) || _consoleMeasuredFontStyle != LogBox.FontStyle ||
            _consoleMeasuredFontWeight != LogBox.FontWeight;
        if (fontChanged)
        {
            var probe = new TextBlock
            {
                Text = "Ag",
                FontFamily = LogBox.FontFamily,
                FontSize = LogBox.FontSize,
                FontStyle = LogBox.FontStyle,
                FontWeight = LogBox.FontWeight
            };
            probe.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
            double measuredLineHeight = probe.DesiredSize.Height;
            if (!double.IsFinite(measuredLineHeight) || measuredLineHeight <= 0) return;
            // Whole physical pixels avoid clipping the twelfth line at
            // fractional scale. Chrome is additional to the text viewport.
            LogBox.LineHeight = Math.Ceiling(measuredLineHeight * scaling) / scaling;
            _consoleMeasuredFontSize = LogBox.FontSize;
            _consoleMeasuredScaling = scaling;
            _consoleMeasuredFontFamily = LogBox.FontFamily;
            _consoleMeasuredFontStyle = LogBox.FontStyle;
            _consoleMeasuredFontWeight = LogBox.FontWeight;
        }

        // Fluent's non-overlay ScrollViewer puts its horizontal bar in a
        // separate auto-sized row. Its real visibility and arranged height
        // can change without a font change, so only the font probe is cached.
        ScrollBar? horizontal = _consoleScrollViewer?.GetVisualDescendants().OfType<ScrollBar>()
            .FirstOrDefault(bar => bar.Orientation == Orientation.Horizontal &&
                ReferenceEquals(bar.TemplatedParent, _consoleScrollViewer));
        double horizontalChrome = horizontal is { IsEffectivelyVisible: true }
            ? horizontal.Bounds.Height + horizontal.Margin.Top + horizontal.Margin.Bottom : 0;
        if (!double.IsFinite(horizontalChrome) || horizontalChrome < 0) return;
        horizontalChrome = Math.Ceiling(horizontalChrome * scaling) / scaling;
        double chrome = LogBox.Padding.Top + LogBox.Padding.Bottom +
                        LogBox.BorderThickness.Top + LogBox.BorderThickness.Bottom + horizontalChrome;
        double height = ConsoleVisibleLines * LogBox.LineHeight + chrome;
        if (!double.IsFinite(height) || height <= 0) return;
        if (Math.Abs(LogBox.MinHeight - height) <= 0.01 && Math.Abs(LogBox.MaxHeight - height) <= 0.01) return;
        _consoleWorkspaceNeedsReveal |= ConsoleExpander.IsExpanded;
        LogBox.MinHeight = height;
        LogBox.MaxHeight = height;
    }

    private void AppendConsoleEntry(string entry)
    {
        lock (_consoleQueueGate)
        {
            if (_disposed) return;
            while (_consolePendingEntries.Count > 0 && _consolePendingCharacters + entry.Length > RetainedLogCharacters)
            {
                _consolePendingCharacters -= _consolePendingEntries.Dequeue().Length;
                _consolePendingPruned = true;
            }
            _consolePendingEntries.Enqueue(entry);
            _consolePendingCharacters += entry.Length;
        }
    }

    private static void FollowConsoleVerticalEnd(ScrollViewer scroller)
    {
        // Automatic following concerns newly appended rows. The native
        // ScrollToEnd API also resets X; keep horizontal reading position.
        scroller.SetCurrentValue(ScrollViewer.OffsetProperty,
            new Vector(scroller.Offset.X, scroller.ScrollBarMaximum.Y));
    }

    private void ConsoleFlushTimer_Tick(object? sender, EventArgs e)
    {
        try { FlushConsoleEntries(); }
        catch { ShowConsoleUnavailable(); }
    }

    private void ShowConsoleUnavailable()
    {
        _consoleObserverUnavailable = true;
        try { ConsoleRetentionText.Text = T("consoleUnavailable"); }
        catch { }
    }

    private void TryRestoreConsoleView(Action restore)
    {
        try { restore(); }
        catch { ShowConsoleUnavailable(); }
    }

    private void FlushConsoleEntries()
    {
        string additions;
        bool pendingPruned;
        lock (_consoleQueueGate)
        {
            if (_consolePendingEntries.Count == 0 || _disposed) return;
            var builder = new StringBuilder(_consolePendingCharacters);
            while (_consolePendingEntries.TryDequeue(out string? entry)) builder.Append(entry);
            additions = builder.ToString();
            _consolePendingCharacters = 0;
            pendingPruned = _consolePendingPruned;
            _consolePendingPruned = false;
        }

        ScrollViewer? scroller = _consoleScrollViewer;
        string existing = LogBox.Text ?? string.Empty;
        int selectionStart = LogBox.SelectionStart;
        int selectionEnd = LogBox.SelectionEnd;
        int caret = LogBox.CaretIndex;
        Vector offset = scroller?.Offset ?? default;
        bool atEnd = scroller is null || offset.Y >= Math.Max(0, scroller.Extent.Height - scroller.Viewport.Height) - 1;
        bool follow = atEnd && selectionStart == selectionEnd;
        if (!ConsoleExpander.IsExpanded) _consoleFollowOnExpansion = follow;
        int removedCharacters = 0;
        if (existing.Length + additions.Length > MaxLogCharacters)
        {
            int start = Math.Max(0, existing.Length - Math.Max(0, RetainedLogCharacters - additions.Length));
            int line = existing.IndexOf('\n', start);
            removedCharacters = line >= 0 ? line + 1 : start;
        }

        double removedHeight = 0;
        if (removedCharacters > 0 && _consoleTextPresenter?.TextLayout is { } layout)
        {
            foreach (var line in layout.TextLines)
            {
                if (line.FirstTextSourceIndex >= removedCharacters) break;
                removedHeight += line.Height;
            }
        }
        _consoleHistoryPruned |= pendingPruned || removedCharacters != 0;
        long version = ++_consoleUpdateVersion;
        long interactionVersion = _consoleInteractionVersion;
        LogBox.Text = existing[removedCharacters..] + additions;
        // Never move a reader's caret to the appended text. After pruning,
        // indices and the rendered offset refer to the retained text only.
        LogBox.CaretIndex = Math.Clamp(caret - removedCharacters, 0, LogBox.Text.Length);
        LogBox.SelectionStart = Math.Clamp(selectionStart - removedCharacters, 0, LogBox.Text.Length);
        LogBox.SelectionEnd = Math.Clamp(selectionEnd - removedCharacters, 0, LogBox.Text.Length);
        ApplyConsoleLanguage();
        Dispatcher.UIThread.Post(() =>
        {
            if (_disposed || version != _consoleUpdateVersion || interactionVersion != _consoleInteractionVersion || scroller is null) return;
            TryRestoreConsoleView(() =>
            {
                if (follow) FollowConsoleVerticalEnd(scroller);
                else scroller.Offset = new Vector(offset.X, Math.Max(0, offset.Y - removedHeight));
            });
        }, DispatcherPriority.Loaded);
    }

    private void ConsoleEnd_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        FlushConsoleEntries();
        long version = ++_consoleUpdateVersion;
        long interactionVersion = _consoleInteractionVersion;
        Dispatcher.UIThread.Post(() =>
        {
            if (!_disposed && version == _consoleUpdateVersion && interactionVersion == _consoleInteractionVersion)
                TryRestoreConsoleView(() => _consoleScrollViewer?.ScrollToEnd());
        }, DispatcherPriority.Loaded);
    }

    private void ClearConsoleLog()
    {
        lock (_consoleQueueGate)
        {
            _consolePendingEntries.Clear();
            _consolePendingCharacters = 0;
            _consolePendingPruned = false;
        }
        ++_consoleUpdateVersion;
        LogBox.Text = string.Empty;
        _consoleHistoryPruned = false;
        _consoleFollowOnExpansion = false;
        ApplyConsoleLanguage();
    }
}
