using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using KalynaArchiver.Services;

namespace KalynaArchiver.Controls;

/// <summary>Windows adapter for the same bounded factor import contract as macOS.</summary>
public sealed class FactorTextBox : TextBox
{
    public static readonly DependencyProperty LanguageCodeProperty = DependencyProperty.Register(
        nameof(LanguageCode), typeof(string), typeof(FactorTextBox), new PropertyMetadata("de", OnLanguageChanged));
    private static readonly DependencyPropertyKey ValidationMessagePropertyKey = DependencyProperty.RegisterReadOnly(
        nameof(ValidationMessage), typeof(string), typeof(FactorTextBox), new PropertyMetadata(string.Empty));
    public static readonly DependencyProperty ValidationMessageProperty = ValidationMessagePropertyKey.DependencyProperty;
    private static readonly DependencyPropertyKey HexCharacterCountPropertyKey = DependencyProperty.RegisterReadOnly(
        nameof(HexCharacterCount), typeof(int), typeof(FactorTextBox), new PropertyMetadata(0));
    public static readonly DependencyProperty HexCharacterCountProperty = HexCharacterCountPropertyKey.DependencyProperty;
    private FactorInput.Error _inputError;

    static FactorTextBox()
    {
        TextProperty.OverrideMetadata(typeof(FactorTextBox), new FrameworkPropertyMetadata(
            string.Empty, FrameworkPropertyMetadataOptions.BindsTwoWayByDefault, null, CoerceFactorText));
        MaxLengthProperty.OverrideMetadata(typeof(FactorTextBox), new FrameworkPropertyMetadata(0, null, (_, _) => 0));
        AcceptsReturnProperty.OverrideMetadata(typeof(FactorTextBox), new FrameworkPropertyMetadata(true, null, (_, _) => true));
    }

    public FactorTextBox()
    {
        AllowDrop = true;
        DataObject.AddPastingHandler(this, OnPasting);
        AddHandler(PreviewDropEvent, new DragEventHandler(OnFactorDrop), handledEventsToo: true);
        AddHandler(PreviewDragOverEvent, new DragEventHandler(OnFactorDragOver), handledEventsToo: true);
    }

    public string LanguageCode { get => (string)GetValue(LanguageCodeProperty); set => SetValue(LanguageCodeProperty, value); }
    public string ValidationMessage => (string)GetValue(ValidationMessageProperty);
    public int HexCharacterCount => (int)GetValue(HexCharacterCountProperty);
    public new string SelectedText { get => base.SelectedText; set => TryReplaceSelection(value); }

    public bool TrySetText(string? text)
    {
        string raw = text ?? string.Empty;
        FactorInput.Error error = FactorInput.Validate(raw.AsSpan(), requireComplete: false, out _);
        if (error != FactorInput.Error.None) { ShowError(error); return false; }
        SetCurrentValue(TextProperty, raw);
        return true;
    }

    public bool TryReplaceSelection(string? insertion)
    {
        if (IsReadOnly || !IsEnabled) return false;
        string raw = insertion ?? string.Empty;
        if (!CanReplaceSelection(raw)) return false;
        base.SelectedText = raw;
        return true;
    }

    private bool CanReplaceSelection(string raw)
    {
        FactorInput.Error error = FactorInput.ValidateReplacement(Text ?? string.Empty,
            SelectionStart, SelectionStart + SelectionLength, raw, out _);
        if (error == FactorInput.Error.None) return true;
        ShowError(error);
        return false;
    }

    protected override void OnPreviewTextInput(TextCompositionEventArgs e)
    {
        if (!e.Handled && !IsReadOnly && !CanReplaceSelection(e.Text ?? string.Empty)) e.Handled = true;
        base.OnPreviewTextInput(e);
    }

    private static object CoerceFactorText(DependencyObject sender, object value)
    {
        var box = (FactorTextBox)sender;
        string raw = value as string ?? string.Empty;
        FactorInput.Error error = FactorInput.Validate(raw.AsSpan(), requireComplete: false, out int count);
        if (error != FactorInput.Error.None) { box.ShowError(error); return box.Text ?? string.Empty; }
        box._inputError = FactorInput.Error.None;
        box.SetValue(HexCharacterCountPropertyKey, count);
        box.RefreshMessage();
        return raw;
    }

    private void OnPasting(object sender, DataObjectPastingEventArgs e)
    {
        e.CancelCommand();
        try
        {
            string? raw = e.DataObject.GetDataPresent(DataFormats.UnicodeText)
                ? e.DataObject.GetData(DataFormats.UnicodeText) as string
                : e.DataObject.GetData(DataFormats.Text) as string;
            if (raw is not null) TryReplaceSelection(raw);
        }
        catch (Exception) { ShowError(FactorInput.Error.TransferFailed); }
    }

    private void OnFactorDragOver(object sender, DragEventArgs e)
    {
        e.Handled = true;
        e.Effects = !IsReadOnly && IsEnabled && e.Data.GetDataPresent(DataFormats.UnicodeText)
            ? DragDropEffects.Copy : DragDropEffects.None;
    }

    private void OnFactorDrop(object sender, DragEventArgs e)
    {
        e.Handled = true;
        e.Effects = DragDropEffects.None;
        try
        {
            string? raw = e.Data.GetData(DataFormats.UnicodeText) as string;
            if (raw is not null && TryReplaceSelection(raw)) e.Effects = DragDropEffects.Copy;
        }
        catch (Exception) { ShowError(FactorInput.Error.TransferFailed); }
    }

    private static void OnLanguageChanged(DependencyObject sender, DependencyPropertyChangedEventArgs e) => ((FactorTextBox)sender).RefreshMessage();
    private void ShowError(FactorInput.Error error) { _inputError = error; RefreshMessage(); }
    private void RefreshMessage() => SetValue(ValidationMessagePropertyKey,
        _inputError == FactorInput.Error.None
            ? LanguageCode == "en" ? $"{HexCharacterCount} / 256 hexadecimal characters" : $"{HexCharacterCount} / 256 Hexadezimalzeichen"
            : FactorInput.Message(_inputError, LanguageCode));
}
