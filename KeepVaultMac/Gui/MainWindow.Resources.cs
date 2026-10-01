using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using KalynaArchiver.Gui;
using KalynaArchiver.Services;

namespace KalynaArchiver;

public sealed partial class MainWindow
{
    private ArchiveOperationPolicy _resourcePolicy = ArchiveOperationPolicy.Current;
    private MacStorageAccessLease? _resourceWorkingAccess;
    private const long ResourceMiB = 1L << 20;

    private void LoadResourcePreferences()
    {
        try
        {
            string? json = _settingsStore.Read(IsolatedStorageAppSettingsStore.ResourcePreferencesKey);
            ResourcePreferences preferences = json is null ? new() :
                JsonSerializer.Deserialize(json, ResourcePreferencesJsonContext.Default.ResourcePreferences) ?? new();
            preferences.Validate();
            _resourcePolicy = new ArchiveOperationPolicy(string.Empty, _resourcePolicy.OutputDirectory, preferences: preferences);
        }
        catch (Exception error) when (error is JsonException or ArgumentException or IOException or OverflowException)
        {
            // Invalid/obsolete preferences never silently activate old time limits.
            _resourcePolicy = new ArchiveOperationPolicy(string.Empty, _resourcePolicy.OutputDirectory, preferences: new());
        }
        DisplayResourcePreferences();
    }

    private void DisplayResourcePreferences()
    {
        ResourcePreferences p = _resourcePolicy.Preferences;
        static string Number(long? value, long scale = 1) => value is null ? string.Empty :
            (value.Value / scale).ToString(CultureInfo.InvariantCulture);
        ResourceWorkersBox.Text = p.CpuMode == ResourceMode.Auto ? string.Empty : Number(p.ManualCpuLimit);
        ResourceMemoryBox.Text = p.MemoryMode == ResourceMode.Auto ? string.Empty : Number(p.ManualMemoryLimitBytes, ResourceMiB);
        ResourceIoBox.Text = p.IoMode == ResourceMode.Auto ? string.Empty : Number(p.ManualIoLimit);
        ResourceQueueBox.Text = p.QueueMode == ResourceMode.Auto ? string.Empty : Number(p.ManualQueueLimit);
        WorkingDirectoryBox.Text = p.WorkingDirectory ?? string.Empty;
        ResourceBudgetBox.Text = Number(p.MaxContainerBytes, ResourceMiB);
        ResourceExtractionBox.Text = Number(p.MaxExtractedTotalBytes, ResourceMiB);
        ResourceSingleFileBox.Text = Number(p.MaxSingleFileBytes, ResourceMiB);
        ResourceRecoveryBox.Text = Number(p.MaxRecoveryBytes, ResourceMiB);
        ResourceMetadataBox.Text = Number(p.MaxMetadataBytes, ResourceMiB);
        ResourceEntriesBox.Text = Number(p.MaxEntryCount);
    }

    private void ApplyResourceLanguage()
    {
        string automatic = IsEnglish ? "Automatic" : "Automatisch";
        ResourcesTab.Header = IsEnglish ? "Resources" : "Ressourcen";
        ResourcesTitle.Text = IsEnglish ? "Automatic resource planning" : "Automatische Ressourcenplanung";
        ResourcesDescription.Text = IsEnglish
            ? "Memory, workers and I/O follow the actual operation and available capacity. A working folder is only used when authenticated metadata must be stored on disk. Argon2id still requires 1 GiB to just under 2 GiB temporarily, plus overhead."
            : "Arbeitsspeicher, Worker und I/O richten sich nach dem tatsächlichen Auftrag und der verfügbaren Kapazität. Ein Arbeitsordner wird erst für notwendige ausgelagerte Prüfmetadaten verwendet. Argon2id benötigt weiterhin vorübergehend 1 GiB bis knapp 2 GiB zuzüglich Betriebsbedarf.";
        ResourceAdvancedExpander.Header = IsEnglish ? "Advanced manual limits" : "Erweiterte manuelle Grenzen";
        WorkingDirectoryLabel.Text = IsEnglish ? "Working folder, only when needed" : "Arbeitsordner, nur bei Bedarf";
        ChooseWorkingDirectoryButton.Content = IsEnglish ? "Choose" : "Auswählen";
        ResourceBudgetLabel.Text = IsEnglish ? "Maximum container size in MiB" : "Containergröße, maximal in MiB";
        ResourceExtractionLabel.Text = IsEnglish ? "Authorized total extraction in MiB" : "Freigegebene gesamte Extraktion in MiB";
        ResourceWorkersLabel.Text = IsEnglish ? "Maximum CPU workers (empty = automatic, minimum 1)" : "CPU-Worker, maximal (leer = automatisch, mindestens 1)";
        ResourceSingleFileLabel.Text = IsEnglish ? "Maximum extracted single file in MiB" : "Extrahierte Einzeldatei, maximal in MiB";
        ResourceRecoveryLabel.Text = IsEnglish ? "Maximum recovery sidecar or repair candidate in MiB" : "Recovery-Sidecar oder Reparaturkandidat, maximal in MiB";
        ResourceMetadataLabel.Text = IsEnglish ? "Maximum metadata in MiB" : "Metadaten, maximal in MiB";
        ResourceMemoryLabel.Text = IsEnglish ? "Maximum working memory in MiB (empty = automatic)" : "Arbeitsspeicher, maximal in MiB (leer = automatisch)";
        ResourceIoLabel.Text = IsEnglish ? "Maximum simultaneous I/O requests" : "Gleichzeitige I/O-Anfragen, maximal";
        ResourceQueueLabel.Text = IsEnglish ? "Maximum in-flight chunks" : "Gleichzeitig verarbeitete Chunks, maximal";
        ResourceEntriesLabel.Text = IsEnglish ? "Maximum extracted files and directories" : "Extrahierte Dateien und Verzeichnisse, maximal";
        ApplyResourcesButton.Content = IsEnglish ? "Save settings" : "Einstellungen speichern";
        ResetResourcesButton.Content = IsEnglish ? "Automatic defaults" : "Automatische Standards";
        foreach (TextBox box in new[] { ResourceWorkersBox, ResourceMemoryBox, ResourceIoBox, ResourceQueueBox, WorkingDirectoryBox })
            box.PlaceholderText = automatic;
        foreach (TextBox box in new[] { ResourceBudgetBox, ResourceRecoveryBox, ResourceMetadataBox, ResourceEntriesBox })
            box.PlaceholderText = IsEnglish ? "Operation-specific" : "Auftragsbezogen";
        ResourceSingleFileBox.PlaceholderText = IsEnglish ? "Same as extraction allowance" : "Wie Extraktionsfreigabe";
        ResourceExtractionBox.PlaceholderText = "256";
        ResourcePreferences p = _resourcePolicy.Preferences;
        string Mode(ResourceMode mode) => mode == ResourceMode.Auto ? automatic : IsEnglish ? "Manual" : "Manuell";
        ResourceModeSummaryText.Text = $"CPU: {Mode(p.CpuMode)} · RAM: {Mode(p.MemoryMode)} · I/O: {Mode(p.IoMode)} · "
            + (IsEnglish ? "Buffers: " : "Puffer: ") + Mode(p.QueueMode);
        string memoryCeiling = (_resourcePolicy.MemoryBudgetBytes / ResourceMiB).ToString(CultureInfo.CurrentCulture);
        ResourceEffectiveSummaryText.Text = IsEnglish
            ? $"Current ceilings: {_resourcePolicy.MaxCpuWorkers} CPU workers, {memoryCeiling} MiB RAM. These values are not reservations; actual allocations follow each phase and current memory pressure."
            : $"Aktuelle Obergrenzen: {_resourcePolicy.MaxCpuWorkers} CPU-Worker, {memoryCeiling} MiB RAM. Diese Werte sind keine Reservierungen; tatsächliche Allokationen folgen der jeweiligen Phase und der aktuellen Speicherauslastung.";
        string allowance = (_resourcePolicy.MaxExtractedTotalBytes / ResourceMiB).ToString(CultureInfo.CurrentCulture);
        ResourceAllowanceText.Text = IsEnglish
            ? $"Extraction allowance: {allowance} MiB. This is a safety limit, not reserved disk space. Unknown output sizes remain unknown; a larger allowance requires your explicit choice. Settings apply to the next operation."
            : $"Extraktionsfreigabe: {allowance} MiB. Das ist eine Sicherheitsgrenze, keine Platzreservierung. Unbekannte Ausgabegrößen bleiben unbekannt; eine höhere Freigabe wählst du ausdrücklich. Einstellungen gelten für den nächsten Vorgang.";
        ResourceOutputAuthorizationText.Text = IsEnglish
            ? $"Current extraction allowance: {allowance} MiB. Change it under Resources when necessary."
            : $"Aktuelle Extraktionsfreigabe: {allowance} MiB. Bei Bedarf unter Ressourcen ändern.";
    }

    private async void ChooseWorkingDirectory_Click(object? sender, RoutedEventArgs e)
    {
        var folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = IsEnglish ? "Choose working folder" : "Arbeitsordner auswählen", AllowMultiple = false,
        });
        foreach (IStorageFolder folder in folders)
        {
            if (GetLocalPath(folder) is { } path && TryAcquireStorageAccess(folder, out MacStorageAccessLease next))
            {
                _resourceWorkingAccess?.Dispose();
                _resourceWorkingAccess = next;
                WorkingDirectoryBox.Text = path;
            }
            else folder.Dispose();
        }
    }

    private async void ApplyResources_Click(object? sender, RoutedEventArgs e)
    {
        try
        {
            long? Optional(TextBox box, long scale = 1)
            {
                string value = box.Text?.Trim() ?? string.Empty;
                if (value.Length == 0) return null;
                if (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out long number) || number <= 0)
                    throw new ArgumentException(IsEnglish ? "Leave automatic fields empty or enter positive whole numbers." : "Lass automatische Felder leer oder gib positive ganze Zahlen ein.");
                return checked(number * scale);
            }
            int? cpu = checked((int?)Optional(ResourceWorkersBox));
            long? memory = Optional(ResourceMemoryBox, ResourceMiB);
            int? io = checked((int?)Optional(ResourceIoBox));
            int? queue = checked((int?)Optional(ResourceQueueBox));
            string working = WorkingDirectoryBox.Text?.Trim() ?? string.Empty;
            if (working.Length > 0 && !Path.IsPathFullyQualified(working))
                throw new ArgumentException(IsEnglish ? "Use an absolute working-folder path or leave the field automatic." : "Verwende einen vollständigen Arbeitsordnerpfad oder lass das Feld automatisch.");
            var preferences = new ResourcePreferences
            {
                CpuMode = cpu.HasValue ? ResourceMode.Manual : ResourceMode.Auto, ManualCpuLimit = cpu,
                MemoryMode = memory.HasValue ? ResourceMode.Manual : ResourceMode.Auto, ManualMemoryLimitBytes = memory,
                IoMode = io.HasValue ? ResourceMode.Manual : ResourceMode.Auto, ManualIoLimit = io,
                QueueMode = queue.HasValue ? ResourceMode.Manual : ResourceMode.Auto, ManualQueueLimit = queue,
                WorkingDirectory = working.Length == 0 ? null : Path.GetFullPath(working),
                MaxContainerBytes = Optional(ResourceBudgetBox, ResourceMiB),
                MaxExtractedTotalBytes = Optional(ResourceExtractionBox, ResourceMiB),
                MaxSingleFileBytes = Optional(ResourceSingleFileBox, ResourceMiB),
                MaxRecoveryBytes = Optional(ResourceRecoveryBox, ResourceMiB),
                MaxMetadataBytes = Optional(ResourceMetadataBox, ResourceMiB),
                MaxEntryCount = Optional(ResourceEntriesBox),
            };
            SaveResourcePreferences(preferences);
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or OverflowException or UnauthorizedAccessException)
        { await WarnAsync(ex.Message); }
    }

    private async void ResetResources_Click(object? sender, RoutedEventArgs e)
    {
        try { SaveResourcePreferences(new()); }
        catch (Exception ex) when (ex is ArgumentException or IOException or OverflowException or UnauthorizedAccessException)
        { await WarnAsync(ex.Message); }
    }

    private void SaveResourcePreferences(ResourcePreferences preferences)
    {
        preferences.Validate();
        var next = new ArchiveOperationPolicy(string.Empty, _resourcePolicy.OutputDirectory, preferences: preferences);
        if (next.EntropyCaptureBudgetBytes < Math.Max(SensitiveMouseRecordStore.Segment.ReservedBytes,
            OperationMemoryBudget.EntropyReservedBytes))
            throw new ArgumentException(IsEnglish
                ? "Finish or explicitly reset protected mouse preparation before reducing memory below its current use."
                : "Beende die geschützte Mausvorbereitung oder setze sie ausdrücklich zurück, bevor du deren Speicher unterschreitest.");
        _settingsStore.Write(IsolatedStorageAppSettingsStore.ResourcePreferencesKey,
            JsonSerializer.Serialize(preferences, ResourcePreferencesJsonContext.Default.ResourcePreferences));
        _resourcePolicy = next;
        DisplayResourcePreferences();
        ApplyResourceLanguage();
        ResourceStatusText.Text = IsEnglish ? "Applied. Actual demand is resolved again for each operation." : "Übernommen. Der tatsächliche Bedarf wird für jeden Vorgang neu ermittelt.";
    }

    private ArchiveOperationPolicy ResourcePolicyForOperation()
    {
        string? output = MainTabs.SelectedItem == ExtractTab ? OutputFolderBox.Text : Path.GetDirectoryName(ArchivePathBox.Text ?? string.Empty);
        return !string.IsNullOrWhiteSpace(output) && Path.IsPathFullyQualified(output)
            ? _resourcePolicy.WithOutputDirectory(output) : _resourcePolicy.WithOutputDirectory(_resourcePolicy.OutputDirectory);
    }
}

[JsonSerializable(typeof(ResourcePreferences))]
internal partial class ResourcePreferencesJsonContext : JsonSerializerContext { }
