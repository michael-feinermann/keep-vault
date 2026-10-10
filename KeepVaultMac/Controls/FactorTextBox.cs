using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Controls.Presenters;
using Avalonia.Controls.Primitives;
using Avalonia.Data;
using Avalonia.Input;
using Avalonia.Input.Platform;
using Avalonia.Input.TextInput;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Threading;
using KalynaArchiver.Services;

namespace KeepVaultMac.Controls;

/// <summary>
/// Public bounded factor-input contract. Composition prevents callers from
/// entering through TextBox.SelectedText, which sanitizes DEL before coercion.
/// The private editor retains the standard style, selection and undo behavior.
/// </summary>
public sealed class FactorTextBox : UserControl
{
    public static readonly StyledProperty<string?> TextProperty =
        AvaloniaProperty.Register<FactorTextBox, string?>(nameof(Text), defaultBindingMode: BindingMode.TwoWay,
            coerce: (owner, value) => ((FactorTextBox)owner).CoerceFactorText(value));
    public static readonly StyledProperty<string> LanguageCodeProperty =
        AvaloniaProperty.Register<FactorTextBox, string>(nameof(LanguageCode), "de");
    public static readonly StyledProperty<bool> AcceptsReturnProperty =
        AvaloniaProperty.Register<FactorTextBox, bool>(nameof(AcceptsReturn), true, coerce: (_, _) => true);
    public static readonly StyledProperty<TextWrapping> TextWrappingProperty =
        TextBox.TextWrappingProperty.AddOwner<FactorTextBox>(new StyledPropertyMetadata<TextWrapping>(TextWrapping.NoWrap));
    public static readonly StyledProperty<bool> IsReadOnlyProperty = TextBox.IsReadOnlyProperty.AddOwner<FactorTextBox>();
    public static readonly DirectProperty<FactorTextBox, string> ValidationMessageProperty =
        AvaloniaProperty.RegisterDirect<FactorTextBox, string>(nameof(ValidationMessage), x => x.ValidationMessage);
    public static readonly DirectProperty<FactorTextBox, int> HexCharacterCountProperty =
        AvaloniaProperty.RegisterDirect<FactorTextBox, int>(nameof(HexCharacterCount), x => x.HexCharacterCount);
    public static readonly DirectProperty<FactorTextBox, bool> IsFormatCompleteProperty =
        AvaloniaProperty.RegisterDirect<FactorTextBox, bool>(nameof(IsFormatComplete), x => x.IsFormatComplete);

    private readonly FactorEditor _editor;
    private AtomicInputMethodClient? _inputMethodClient;
    private string _validationMessage = string.Empty;
    private int _hexCharacterCount;
    private bool _isFormatComplete;
    private FactorInput.Error _inputError;
    private long _editRevision;

    public FactorTextBox()
    {
        _editor = new FactorEditor(this)
        {
            AcceptsReturn = true, MaxLength = 0, MaxLines = 6,
            FontFamily = FontFamily, TextWrapping = TextWrapping.NoWrap
        };
        ScrollViewer.SetHorizontalScrollBarVisibility(_editor, ScrollBarVisibility.Auto);
        ScrollViewer.SetVerticalScrollBarVisibility(_editor, ScrollBarVisibility.Auto);
        Content = _editor;
        _editor.PastingFromClipboard += OnPastingFromClipboard;
        _editor.TextInputMethodClientRequested += OnInputMethodClientRequested;
        DragDrop.SetAllowDrop(this, true);
        DragDrop.SetAllowDrop(_editor, true);
        AddHandler(DragDrop.DropEvent, OnDrop, RoutingStrategies.Bubble, handledEventsToo: true);
        AddHandler(DragDrop.DragOverEvent, OnDragOver, RoutingStrategies.Bubble, handledEventsToo: true);
        RefreshMessage();
    }

    public string? Text { get => GetValue(TextProperty); set => SetValue(TextProperty, value); }
    public string LanguageCode { get => GetValue(LanguageCodeProperty); set => SetValue(LanguageCodeProperty, value); }
    public bool AcceptsReturn { get => GetValue(AcceptsReturnProperty); set => SetValue(AcceptsReturnProperty, value); }
    public TextWrapping TextWrapping { get => GetValue(TextWrappingProperty); set => SetValue(TextWrappingProperty, value); }
    public bool IsReadOnly { get => GetValue(IsReadOnlyProperty); set => SetValue(IsReadOnlyProperty, value); }
    public int MaxLength => 0;
    public string ValidationMessage => _validationMessage;
    public int HexCharacterCount => _hexCharacterCount;
    public bool IsFormatComplete => _isFormatComplete;
    public int SelectionStart { get => _editor.SelectionStart; set => _editor.SelectionStart = value; }
    public int SelectionEnd { get => _editor.SelectionEnd; set => _editor.SelectionEnd = value; }
    public int CaretIndex { get => _editor.CaretIndex; set => _editor.CaretIndex = value; }
    public string SelectedText { get => _editor.SelectedText; set => TryReplaceSelection(value); }
    public new bool Focus(NavigationMethod method = NavigationMethod.Unspecified, KeyModifiers modifiers = KeyModifiers.None)
        => _editor.Focus(method, modifiers);
    public void SelectAll() => _editor.SelectAll();
    public void Undo() => _editor.Undo();
    public void Redo() => _editor.Redo();
    public void Paste() => _editor.Paste();

    /// <summary>Explicit secret clearing also removes the native undo/redo history, even if text is already empty.</summary>
    public void ClearSensitiveText()
    {
        // An explicit clear invalidates outstanding clipboard transfers even
        // when no Text/caret/selection property needs to change.
        ++_editRevision;
        bool undoEnabled = _editor.IsUndoEnabled;
        // Avalonia documents this property transition as clearing its existing
        // undo/redo queue. It neither introduces another history nor relies on
        // a same-value outer Text assignment firing an editor change event.
        _editor.SetCurrentValue(TextBox.IsUndoEnabledProperty, false);
        try
        {
            _editor.SetCurrentValue(TextBox.TextProperty, string.Empty);
            SetCurrentValue(TextProperty, string.Empty);
            _editor.CaretIndex = _editor.SelectionStart = _editor.SelectionEnd = 0;
        }
        finally { _editor.SetCurrentValue(TextBox.IsUndoEnabledProperty, undoEnabled); }
    }

    public bool TrySetText(string? text)
    {
        FactorInput.Error error = FactorInput.Validate((text ?? string.Empty).AsSpan(), requireComplete: false, out _);
        if (error != FactorInput.Error.None) { ShowError(error); return false; }
        SetCurrentValue(TextProperty, text);
        return true;
    }

    public bool TryReplaceSelection(string? insertion)
    {
        if (IsReadOnly || !IsEffectivelyEnabled) return false;
        string raw = insertion ?? string.Empty;
        if (!CanReplaceSelection(raw)) return false;
        _editor.SelectedText = raw;
        CompleteAcceptedInput();
        return true;
    }

    // Explicitly accepted input can replace a factor with identical text, so
    // no Text change/coercion need occur to clear an earlier import error.
    private void CompleteAcceptedInput()
    {
        if (_inputError != FactorInput.Error.None)
        {
            _inputError = FactorInput.Error.None;
            RefreshMessage();
        }
    }

    private bool CanReplaceSelection(string raw)
    {
        FactorInput.Error error = FactorInput.ValidateReplacement(_editor.Text ?? string.Empty,
            Math.Min(SelectionStart, SelectionEnd), Math.Max(SelectionStart, SelectionEnd), raw, out _);
        if (error == FactorInput.Error.None) return true;
        ShowError(error);
        return false;
    }

    private string? CoerceFactorText(string? value)
    {
        FactorInput.Error error = FactorInput.Validate((value ?? string.Empty).AsSpan(), requireComplete: false, out int count);
        if (error != FactorInput.Error.None) { ShowError(error); return Text; }
        _inputError = FactorInput.Error.None;
        SetAndRaise(HexCharacterCountProperty, ref _hexCharacterCount, count);
        RefreshMessage();
        return value;
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (_editor is null) return; // Property initialization can precede the constructor body.
        if (change.Property == TextProperty && _editor.Text != Text) _editor.SetCurrentValue(TextBox.TextProperty, Text);
        if (change.Property == LanguageCodeProperty) RefreshMessage();
        if (change.Property == FontFamilyProperty) _editor.SetCurrentValue(FontFamilyProperty, FontFamily);
        if (change.Property == TextWrappingProperty)
        {
            _editor.SetCurrentValue(TextBox.TextWrappingProperty, TextWrapping);
            ScrollViewer.SetHorizontalScrollBarVisibility(_editor,
                TextWrapping == TextWrapping.NoWrap ? ScrollBarVisibility.Auto : ScrollBarVisibility.Disabled);
        }
        if (change.Property == IsReadOnlyProperty) _editor.SetCurrentValue(TextBox.IsReadOnlyProperty, IsReadOnly);
        if (change.Property == AutomationProperties.LabeledByProperty)
            AutomationProperties.SetLabeledBy(_editor, AutomationProperties.GetLabeledBy(this));
        if (change.Property == AutomationProperties.HelpTextProperty)
            AutomationProperties.SetHelpText(_editor, AutomationProperties.GetHelpText(this));
        if (change.Property == AutomationProperties.NameProperty)
            AutomationProperties.SetName(_editor, AutomationProperties.GetName(this));
    }

    private void OnInputMethodClientRequested(object? sender, TextInputMethodClientRequestedEventArgs e)
    {
        if (e.Client is not { } inner || inner == _inputMethodClient) return;
        if (_inputMethodClient is null || !_inputMethodClient.Wraps(inner))
        {
            _inputMethodClient?.Dispose();
            _inputMethodClient = new AtomicInputMethodClient(inner);
        }
        e.Client = _inputMethodClient;
    }

    private void OnPastingFromClipboard(object? sender, RoutedEventArgs e)
    {
        e.Handled = true;
        _ = PasteAtomicallyAsync();
    }

    private async Task PasteAtomicallyAsync()
    {
        if (IsReadOnly || !IsEffectivelyEnabled) return;
        long revision = _editRevision;
        try
        {
            var clipboard = TopLevel.GetTopLevel(this)?.Clipboard;
            if (clipboard is null) return;
            string? raw = await clipboard.TryGetTextAsync();
            if (revision != _editRevision) { ShowError(FactorInput.Error.StaleTransfer); return; }
            if (raw is not null) TryReplaceSelection(raw);
        }
        catch (Exception) { ShowError(FactorInput.Error.TransferFailed); }
    }

    private void OnDragOver(object? sender, DragEventArgs e)
    {
        e.Handled = true;
        e.DragEffects = !IsReadOnly && IsEffectivelyEnabled && e.DataTransfer.Contains(DataFormat.Text)
            ? DragDropEffects.Copy : DragDropEffects.None;
    }

    private void OnDrop(object? sender, DragEventArgs e)
    {
        e.Handled = true;
        e.DragEffects = DragDropEffects.None;
        try
        {
            string? raw = e.DataTransfer.TryGetText();
            if (raw is not null && TryReplaceSelection(raw)) e.DragEffects = DragDropEffects.Copy;
        }
        catch (Exception) { ShowError(FactorInput.Error.TransferFailed); }
    }

    private void ShowError(FactorInput.Error error) { _inputError = error; RefreshMessage(); }
    private void RefreshMessage()
    {
        SetAndRaise(IsFormatCompleteProperty, ref _isFormatComplete,
            _inputError == FactorInput.Error.None && _hexCharacterCount == FactorInput.HexLength);
        string message = _inputError == FactorInput.Error.None
            ? LanguageCode == "en" ? $"{_hexCharacterCount} / 256 hexadecimal characters" : $"{_hexCharacterCount} / 256 Hexadezimalzeichen"
            : FactorInput.Message(_inputError, LanguageCode);
        SetAndRaise(ValidationMessageProperty, ref _validationMessage, message);
    }

    /// <summary>
    /// Keep IME commit and normal geometry/selection notifications, while never
    /// letting preliminary composition text delete a selected accepted factor.
    /// No preedit text or prior factor string is stored by this adapter.
    /// </summary>
    private sealed class AtomicInputMethodClient : TextInputMethodClient, IDisposable
    {
        private readonly TextInputMethodClient _inner;
        internal AtomicInputMethodClient(TextInputMethodClient inner)
        {
            _inner = inner;
            inner.TextViewVisualChanged += ViewChanged;
            inner.CursorRectangleChanged += CursorChanged;
            inner.SurroundingTextChanged += TextChanged;
            inner.SelectionChanged += SelectionChangedHandler;
            inner.ResetRequested += Reset;
            inner.InputPaneActivationRequested += Activate;
        }
        internal bool Wraps(TextInputMethodClient inner) => ReferenceEquals(_inner, inner);
        public override Visual TextViewVisual => _inner.TextViewVisual;
        public override bool SupportsPreedit => false;
        public override bool SupportsSurroundingText => _inner.SupportsSurroundingText;
        public override string SurroundingText => _inner.SurroundingText;
        public override Rect CursorRectangle => _inner.CursorRectangle;
        public override TextSelection Selection { get => _inner.Selection; set => _inner.Selection = value; }
        public override void SetPreeditText(string? preeditText) { }
        public override void SetPreeditText(string? preeditText, int? cursorPos) { }
        public override void ExecuteContextMenuAction(ContextMenuAction action) => _inner.ExecuteContextMenuAction(action);
        private void ViewChanged(object? sender, EventArgs e) => RaiseTextViewVisualChanged();
        private void CursorChanged(object? sender, EventArgs e) => RaiseCursorRectangleChanged();
        private void TextChanged(object? sender, EventArgs e) => RaiseSurroundingTextChanged();
        private void SelectionChangedHandler(object? sender, EventArgs e) => RaiseSelectionChanged();
        private void Reset(object? sender, EventArgs e) => RequestReset();
        private void Activate(object? sender, EventArgs e) => RaiseInputPaneActivationRequested();
        public void Dispose()
        {
            _inner.TextViewVisualChanged -= ViewChanged;
            _inner.CursorRectangleChanged -= CursorChanged;
            _inner.SurroundingTextChanged -= TextChanged;
            _inner.SelectionChanged -= SelectionChangedHandler;
            _inner.ResetRequested -= Reset;
            _inner.InputPaneActivationRequested -= Activate;
        }
    }

    private sealed class FactorEditor(FactorTextBox owner) : TextBox
    {
        private TextPresenter? _presenter;
        private bool _restoreQueued;
        protected override Type StyleKeyOverride => typeof(TextBox);
        protected override string? CoerceText(string? value)
        {
            FactorInput.Error error = FactorInput.Validate((value ?? string.Empty).AsSpan(), requireComplete: false, out _);
            if (error == FactorInput.Error.None) return base.CoerceText(value);
            owner.ShowError(error);
            QueuePresenterRestore();
            return Text;
        }
        protected override void OnTextInput(TextInputEventArgs e)
        {
            if (e.Handled) { base.OnTextInput(e); return; }
            if (IsReadOnly || !owner.IsEffectivelyEnabled) { e.Handled = true; return; }
            string raw = e.Text ?? string.Empty;
            if (!owner.CanReplaceSelection(raw))
            { e.Handled = true; return; }
            base.OnTextInput(e);
            // Preserve the base editor's caret, selection and undo processing.
            // An empty TextInput is ignored by the base and is no new import.
            if (raw.Length > 0 && e.Handled) owner.CompleteAcceptedInput();
        }
        protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
        {
            // The base TextBox synchronously coerces caret and selection after
            // a text commit. Its template binding may still expose the previous
            // text at that point, forcing a stale (potentially 65,536-character)
            // layout when ClearSelection moves the presenter caret. Synchronize
            // the fully validated committed value before that base processing.
            // This is presentation ordering only; base editing/history remains
            // authoritative and the complete raw value is preserved.
            if (change.Property == TextBox.TextProperty)
                _presenter?.SetCurrentValue(TextPresenter.TextProperty, Text);
            base.OnPropertyChanged(change);
            if (change.Property == TextProperty || change.Property == SelectionStartProperty
                || change.Property == SelectionEndProperty || change.Property == CaretIndexProperty)
                owner._editRevision++;
            // Avalonia's TextChanged event is posted asynchronously. Publish
            // the accepted editor value at the synchronous property boundary.
            if (change.Property == TextBox.TextProperty && owner.Text != Text)
                owner.SetCurrentValue(FactorTextBox.TextProperty, Text);
        }
        protected override void OnApplyTemplate(TemplateAppliedEventArgs e)
        {
            base.OnApplyTemplate(e);
            _presenter = e.NameScope.Find<TextPresenter>("PART_TextPresenter");
        }
        private void QueuePresenterRestore()
        {
            if (_restoreQueued) return;
            _restoreQueued = true;
            long revision = owner._editRevision;
            Dispatcher.UIThread.Post(() =>
            {
                _restoreQueued = false;
                if (owner._editRevision != revision) return;
                // No saved cursor is written back. A later cursor/selection or
                // accepted edit makes this visual synchronization obsolete.
                _presenter?.SetCurrentValue(TextPresenter.TextProperty, Text);
            });
        }
    }
}
