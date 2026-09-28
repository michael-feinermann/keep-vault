using System.Globalization;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using KalynaArchiver.Gui;
using KalynaArchiver.Services;

namespace KalynaArchiver;

public sealed partial class MainWindow
{
    private ArchiveOperationPolicy _resourcePolicy = ArchiveOperationPolicy.Current;
    private MacStorageAccessLease? _resourceWorkingAccess;

    private void ApplyResourceLanguage()
    {
        ResourcesTab.Header = IsEnglish ? "Resources" : "Ressourcen";
        ResourcesTitle.Text = IsEnglish ? "Working folder and limits" : "Arbeitsordner und Grenzen";
        ResourcesDescription.Text = IsEnglish
            ? "Choose a local working folder with sufficient free space. Limits apply to the next operation. The extraction destination is selected on the Extract tab. No files are deleted to make room."
            : "Wähle einen lokalen Arbeitsordner mit genügend freiem Platz. Die Grenzen gelten für den nächsten Vorgang. Das Ausgabeziel wählst du unter Extraktion. Es werden keine Dateien gelöscht, um Platz zu schaffen.";
        WorkingDirectoryLabel.Text = IsEnglish ? "Working folder" : "Arbeitsordner";
        ChooseWorkingDirectoryButton.Content = IsEnglish ? "Choose" : "Auswählen";
        ResourceBudgetLabel.Text = IsEnglish ? "Maximum archive and total extraction size in GiB" : "Archiv und gesamte Extraktion, maximal in GiB";
        ResourceHoursLabel.Text = IsEnglish ? "Maximum elapsed time in hours" : "Laufzeit, maximal in Stunden";
        ResourceWorkersLabel.Text = IsEnglish ? "Maximum CPU workers (0 = automatic, otherwise at least 2)" : "CPU-Worker, maximal (0 = automatisch, sonst mindestens 2)";
        ResourceSingleFileLabel.Text = IsEnglish ? "Maximum single file in GiB" : "Einzeldatei, maximal in GiB";
        ResourceRecoveryLabel.Text = IsEnglish ? "Maximum recovery sidecar or repair candidate in GiB" : "Recovery-Sidecar oder Reparaturkandidat, maximal in GiB";
        ResourceMetadataLabel.Text = IsEnglish ? "Maximum temporary metadata in GiB" : "Temporäre Metadaten, maximal in GiB";
        ResourceMemoryLabel.Text = IsEnglish ? "Memory budget in GiB" : "Arbeitsspeicherbudget in GiB";
        ResourceIoLabel.Text = IsEnglish ? "Simultaneous I/O requests" : "Gleichzeitige I/O-Anfragen";
        ResourceQueueLabel.Text = IsEnglish ? "Queued chunks" : "Bereitgehaltene Chunks";
        ResourceEntriesLabel.Text = IsEnglish ? "Maximum files and directories" : "Dateien und Verzeichnisse, maximal";
        ApplyResourcesButton.Content = IsEnglish ? "Apply for this session" : "Für diese Sitzung übernehmen";
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
            if (!long.TryParse(ResourceBudgetBox.Text, NumberStyles.None, CultureInfo.InvariantCulture, out long gib) || gib <= 0
                || !int.TryParse(ResourceHoursBox.Text, NumberStyles.None, CultureInfo.InvariantCulture, out int hours) || hours <= 0
                || !int.TryParse(ResourceWorkersBox.Text, NumberStyles.None, CultureInfo.InvariantCulture, out int workers) || workers < 0 || workers == 1)
                throw new ArgumentException(IsEnglish ? "Enter positive whole numbers." : "Gib positive ganze Zahlen ein.");
            string working = WorkingDirectoryBox.Text?.Trim() ?? string.Empty;
            if (!Path.IsPathFullyQualified(working) || !Directory.Exists(working))
                throw new ArgumentException(IsEnglish ? "Choose an existing absolute working folder." : "Wähle einen vorhandenen Arbeitsordner mit vollständigem Pfad.");
            static long Positive(string? value)
            {
                if (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out long result) || result <= 0)
                    throw new ArgumentException("Resource limits must be positive whole numbers.");
                return result;
            }
            long bytes = checked(gib * (1L << 30));
            long singleFile = checked(Positive(ResourceSingleFileBox.Text) * (1L << 30));
            long recovery = checked(Positive(ResourceRecoveryBox.Text) * (1L << 30));
            long metadata = checked(Positive(ResourceMetadataBox.Text) * (1L << 30));
            long memory = checked(Positive(ResourceMemoryBox.Text) * (1L << 30));
            int io = checked((int)Positive(ResourceIoBox.Text));
            int queued = checked((int)Positive(ResourceQueueBox.Text));
            long entries = Positive(ResourceEntriesBox.Text);
            var next = new ArchiveOperationPolicy(working, _resourcePolicy.OutputDirectory,
                maxContainerBytes: bytes, maxExtractedTotalBytes: bytes, maxSingleFileBytes: singleFile,
                maxRecoveryBytes: recovery, maxMetadataBytes: metadata, maxEntryCount: entries,
                memoryBudgetBytes: memory, maxCpuWorkers: workers, maxIoRequests: io,
                maxQueuedChunks: queued, wallTimeBudget: TimeSpan.FromHours(hours),
                cpuTimeBudget: TimeSpan.FromHours(checked((long)hours * (workers == 0 ? Math.Max(1, Environment.ProcessorCount) : workers))));
            if (next.EntropyCaptureBudgetBytes < SensitiveMouseRecordStore.Segment.ReservedBytes)
                throw new ArgumentException(IsEnglish
                    ? "The memory budget is below the current protected mouse data. Finish or explicitly reset preparation before reducing it."
                    : "Das Speicherbudget unterschreitet die geschützten Mausdaten. Beende die Vorbereitung oder setze sie ausdrücklich zurück, bevor du es reduzierst.");
            _resourcePolicy = next;
            ResourceStatusText.Text = IsEnglish
                ? $"Applied: {gib} GiB, {hours} h, up to {next.MaxCpuWorkers} workers. Available space and format limits are checked for each operation."
                : $"Übernommen: {gib} GiB, {hours} h, bis zu {next.MaxCpuWorkers} Worker. Verfügbarer Platz und Formatgrenzen werden pro Vorgang geprüft.";
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or OverflowException or UnauthorizedAccessException)
        {
            await WarnAsync(ex.Message);
        }
    }

    private ArchiveOperationPolicy ResourcePolicyForOperation()
    {
        string? output = MainTabs.SelectedItem == ExtractTab ? OutputFolderBox.Text : Path.GetDirectoryName(ArchivePathBox.Text ?? string.Empty);
        return !string.IsNullOrWhiteSpace(output) && Path.IsPathFullyQualified(output)
            ? _resourcePolicy.WithOutputDirectory(output) : _resourcePolicy;
    }
}
