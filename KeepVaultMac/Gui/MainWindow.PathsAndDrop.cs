using Avalonia.Input;
using Avalonia.Platform.Storage;

namespace KalynaArchiver;

public sealed partial class MainWindow
{
    internal static string NormalizeTargetArchivePath(string path, bool encrypted)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return string.Empty;
        }

        string trimmed = path.Trim();
        string extension = encrypted ? ".kzpaq" : ".zpaq";
        if (Directory.Exists(trimmed) && !HasArchiveExtension(trimmed))
        {
            return Path.Combine(trimmed, $"archive{extension}");
        }

        return string.Equals(Path.GetExtension(trimmed), extension, StringComparison.OrdinalIgnoreCase)
            ? trimmed
            : Path.ChangeExtension(trimmed, extension);
    }

    internal static string SuggestTargetArchivePath(string source, bool encrypted)
    {
        if (string.IsNullOrWhiteSpace(source))
        {
            return string.Empty;
        }

        string full = Path.GetFullPath(source.Trim());
        string extension = encrypted ? ".kzpaq" : ".zpaq";
        if (Directory.Exists(full))
        {
            // Beside the folder, named after it — not inside it. An archive
            // created inside its own input is refused a moment later by the
            // safety check, so suggesting one only ever produced a dead end.
            // Naming it after the folder also keeps it distinct from anything
            // else of that name: a folder "Docs" and a file "Docs.zip" can sit
            // side by side, and so can the "Docs(1).kzpaq" made from either.
            string trimmed = Path.TrimEndingDirectorySeparator(full);
            string? parent = Path.GetDirectoryName(trimmed);
            string folderName = Path.GetFileName(trimmed);
            return string.IsNullOrEmpty(parent) || string.IsNullOrWhiteSpace(folderName)
                ? BuildNumberedArchivePath(full, "archive", extension)
                : BuildNumberedArchivePath(parent, folderName, extension);
        }

        string directory = Path.GetDirectoryName(full) ?? Environment.CurrentDirectory;
        string stem = Path.GetFileNameWithoutExtension(full);
        return BuildNumberedArchivePath(directory, string.IsNullOrWhiteSpace(stem) ? "archive" : stem, extension);
    }

    /// <summary>
    /// Suggests a new archive inside a destination folder selected by the
    /// user. This is deliberately distinct from <see cref="SuggestTargetArchivePath"/>,
    /// whose directory argument denotes an input folder and therefore has to
    /// place the archive beside that input.
    /// </summary>
    internal static string SuggestArchivePathInDestinationFolder(string destinationFolder, bool encrypted)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(destinationFolder);
        string full = Path.GetFullPath(destinationFolder.Trim());
        if (!Directory.Exists(full))
        {
            throw new DirectoryNotFoundException($"Der gewählte Archiv-Zielordner existiert nicht: {full}");
        }

        return BuildNumberedArchivePath(full, "archive", encrypted ? ".kzpaq" : ".zpaq");
    }

    internal static string SuggestOutputFolderPath(string archivePath)
    {
        if (string.IsNullOrWhiteSpace(archivePath))
        {
            return string.Empty;
        }

        string full = Path.GetFullPath(archivePath.Trim());
        string directory = Path.GetDirectoryName(full) ?? Environment.CurrentDirectory;
        string stem = Path.GetFileNameWithoutExtension(full);
        return BuildNumberedDirectoryPath(directory, string.IsNullOrWhiteSpace(stem) ? "extract" : stem);
    }

    internal static string SuggestOutputFolderPath(string archivePath, string parentDirectory)
    {
        string parent = Path.GetFullPath(parentDirectory.Trim());
        if (!Directory.Exists(parent))
        {
            throw new DirectoryNotFoundException($"Der gewählte übergeordnete Zielordner existiert nicht: {parent}");
        }

        string stem = string.IsNullOrWhiteSpace(archivePath)
            ? "extract"
            : Path.GetFileNameWithoutExtension(archivePath.Trim());
        return BuildNumberedDirectoryPath(parent, string.IsNullOrWhiteSpace(stem) ? "extract" : stem);
    }

    internal static bool HasEncryptedArchiveExtension(string path) =>
        string.Equals(Path.GetExtension(path), ".kzpaq", StringComparison.OrdinalIgnoreCase);

    internal static bool HasArchiveExtension(string path)
    {
        string extension = Path.GetExtension(path);
        return string.Equals(extension, ".kzpaq", StringComparison.OrdinalIgnoreCase)
            || string.Equals(extension, ".zpaq", StringComparison.OrdinalIgnoreCase);
    }

    private static string BuildNumberedArchivePath(string directory, string stem, string extension)
    {
        for (int index = 1; index < int.MaxValue; index++)
        {
            string candidate = Path.Combine(directory, $"{stem}({index}){extension}");
            if (!File.Exists(candidate) && !Directory.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new IOException("Kein freier nummerierter Archivname verfügbar.");
    }

    private static string BuildNumberedDirectoryPath(string directory, string stem)
    {
        for (int index = 1; index < int.MaxValue; index++)
        {
            string candidate = Path.Combine(directory, $"{stem}({index})");
            if (!File.Exists(candidate) && !Directory.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new IOException("Kein freier nummerierter Zielordner verfügbar.");
    }

    private int AddInputPaths(IEnumerable<string> paths)
    {
        int added = 0;
        string? first = null;
        foreach (string source in paths)
        {
            string path;
            try
            {
                path = Path.GetFullPath(source);
            }
            catch
            {
                continue;
            }

            if (!File.Exists(path) && !Directory.Exists(path))
            {
                continue;
            }

            first ??= path;
            if (!InputList.Items.OfType<string>().Contains(path, StringComparer.Ordinal))
            {
                InputList.Items.Add(path);
                added++;
            }
        }

        if (first is not null && string.IsNullOrWhiteSpace(ArchivePathBox.Text))
        {
            ArchivePathBox.Text = SuggestTargetArchivePath(first, EncryptBox.IsChecked == true);
            ResetKeySheetStatus();
        }

        if (added > 0)
        {
            Log(string.Format(System.Globalization.CultureInfo.CurrentCulture, T("dropAddedInputs"), added));
        }

        return added;
    }

    private void EnsureArchiveTargetIsSafe(string archivePath, IReadOnlyList<string> inputs)
    {
        string target = Path.GetFullPath(archivePath);
        if (File.Exists(target) || Directory.Exists(target))
        {
            throw new InvalidOperationException(T("archiveTargetExists"));
        }

        foreach (string input in inputs)
        {
            string fullInput = Path.GetFullPath(input);
            if (File.Exists(fullInput) && string.Equals(target, fullInput, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(T("archiveTargetOverwritesInput"));
            }

            if (Directory.Exists(fullInput) && IsInsideDirectory(target, fullInput))
            {
                throw new InvalidOperationException(T("archiveTargetInsideInput"));
            }
        }
    }

    private static bool IsInsideDirectory(string path, string directory)
    {
        string normalizedPath = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar);
        string normalizedDirectory = Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return normalizedPath.StartsWith(normalizedDirectory, StringComparison.Ordinal);
    }

    private void SetDropEffectAndLog(DragEventArgs e, MacDropTarget target)
    {
        // DragOver only borrows provider items. Refusal must neither acquire
        // nor dispose them before a possible later Drop owns the batch.
        e.DragEffects = DragDropEffects.None;
        e.Handled = true;
        if (_disposed) return;
        try
        {
            IReadOnlyList<IStorageItem> items = e.DataTransfer.TryGetFiles() ?? [];
            string[] paths = items.Select(GetLocalPath).OfType<string>().ToArray();
            MacDropTarget effective = target == MacDropTarget.ExtractPanelAuto
                ? paths.Any(HasArchiveExtension) ? MacDropTarget.ExtractArchive : MacDropTarget.OutputFolder
                : target;
            e.DragEffects = CanDrop(items, paths, effective) ? DragDropEffects.Copy : DragDropEffects.None;
        }
        // Hover can repeat before Drop. Its refusal belongs in the bounded
        // console, without opening repeated modal selection-failure dialogs.
        catch (Exception failure) { Log(failure.ToString()); }
    }

    private static bool CanDrop(
        IReadOnlyList<IStorageItem> items,
        IReadOnlyList<string> paths,
        MacDropTarget target) => target switch
    {
        MacDropTarget.Inputs => items.Any(item => item is IStorageFile or IStorageFolder),
        MacDropTarget.TargetArchive => items.Count == 1 && paths.Count == 1,
        MacDropTarget.ExtractArchive => paths.Any(HasArchiveExtension),
        MacDropTarget.OutputFolder => items.Any(item => item is IStorageFolder),
        MacDropTarget.EraseTarget => items.Any(item => item is IStorageFile),
        MacDropTarget.Auto => paths.Count > 0,
        _ => false,
    };

    private void ApplyDrop(DragEventArgs e, MacDropTarget target)
    {
        IStorageItem[] items = (e.DataTransfer.TryGetFiles() ?? [])
            .Distinct<IStorageItem>(ReferenceEqualityComparer.Instance).ToArray();
        var consumed = new HashSet<IStorageItem>(ReferenceEqualityComparer.Instance);
        List<Exception>? failures = null;
        e.DragEffects = DragDropEffects.None;
        e.Handled = true;
        try
        {
            // Path is provider code too: every captured item is already within
            // the cleanup scope before any provider callback can fail.
            string[] paths = items.Select(GetLocalPath).OfType<string>().ToArray();
            if (!_disposed)
            {
                MacDropTarget effective = target == MacDropTarget.Auto
                    ? paths.Any(HasArchiveExtension) ? MacDropTarget.ExtractArchive : MacDropTarget.Inputs
                    : target == MacDropTarget.ExtractPanelAuto
                        ? paths.Any(HasArchiveExtension) ? MacDropTarget.ExtractArchive : MacDropTarget.OutputFolder
                    : target;
                bool applied = effective switch
                {
                    MacDropTarget.Inputs => ApplyInputDrop(items, consumed),
                    MacDropTarget.TargetArchive => ApplyArchiveTargetDrop(items, paths, consumed),
                    MacDropTarget.ExtractArchive => ApplyExtractDrop(items, paths, consumed),
                    MacDropTarget.OutputFolder => ApplyOutputDrop(items, paths, consumed),
                    MacDropTarget.EraseTarget => ApplyEraseDrop(items, paths, consumed),
                    _ => false,
                };
                e.DragEffects = applied ? DragDropEffects.Copy : DragDropEffects.None;
            }
        }
        catch (Exception failure) { (failures ??= []).Add(failure); }
        finally
        {
            try { DisposeUnretainedStorageItems(items.Where(item => !consumed.Contains(item))); }
            catch (Exception failure) { (failures ??= []).Add(failure); }
        }
        if (failures is not null) throw new AggregateException("Drop ownership update failed.", failures);
    }

    private bool ApplyInputDrop(IReadOnlyList<IStorageItem> items, ISet<IStorageItem> consumed)
    {
        // AddInputStorageItems owns every item, including refused/faulted paths.
        foreach (IStorageItem item in items) consumed.Add(item);
        return AddInputStorageItems(items) > 0;
    }

    private bool ApplyArchiveTargetDrop(IReadOnlyList<IStorageItem> items, IReadOnlyList<string> paths, ISet<IStorageItem> consumed)
    {
        if (paths.Count != 1)
        {
            return false;
        }

        string path = paths[0];
        IStorageItem? selectedItem = items.FirstOrDefault(item => StorageItemNamesPath(item, path));
        if (selectedItem is IStorageFile && !HasArchiveExtension(path))
        {
            consumed.Add(selectedItem);
            AddInputStorageItems([selectedItem]);
            if (!IsStorageAccessRetained(selectedItem)) return false;
        }
        else if (selectedItem is IStorageFolder folder)
        {
            consumed.Add(folder);
            if (!RetainArchiveDestinationAccess(folder))
            {
                return false;
            }
        }

        ArchivePathBox.Text = SuggestTargetArchivePath(path, EncryptBox.IsChecked == true);
        ResetKeySheetStatus();
        Log(string.Format(System.Globalization.CultureInfo.CurrentCulture, T("dropTargetArchive"), ArchivePathBox.Text));
        return true;
    }

    private bool ApplyExtractDrop(IReadOnlyList<IStorageItem> items, IEnumerable<string> paths, ISet<IStorageItem> consumed)
    {
        string? archive = paths.FirstOrDefault(HasArchiveExtension);
        if (archive is null)
        {
            return false;
        }

        if (items.FirstOrDefault(item => StorageItemNamesPath(item, archive)) is IStorageFile file)
        {
            consumed.Add(file);
            if (!RetainExtractArchiveAccess(file))
            {
                return false;
            }
        }
        else
        {
            return false;
        }

        SetExtractArchivePath(archive);
        MainTabs.SelectedItem = ExtractTab;
        Log(string.Format(System.Globalization.CultureInfo.CurrentCulture, T("dropExtractArchive"), archive));
        return true;
    }

    private bool ApplyOutputDrop(IReadOnlyList<IStorageItem> items, IEnumerable<string> paths, ISet<IStorageItem> consumed)
    {
        IStorageFolder? storageFolder = items.OfType<IStorageFolder>().FirstOrDefault();
        string? folder = storageFolder is null ? null : GetLocalPath(storageFolder);
        if (storageFolder is null || folder is null)
        {
            return false;
        }

        consumed.Add(storageFolder);
        if (!RetainExtractOutputParentAccess(storageFolder))
        {
            return false;
        }

        string output = SuggestOutputFolderPath(ExtractArchiveBox.Text ?? string.Empty, folder);
        OutputFolderBox.Text = output;
        Log(string.Format(System.Globalization.CultureInfo.CurrentCulture, T("dropOutputFolder"), output));
        return true;
    }

    private bool ApplyEraseDrop(IReadOnlyList<IStorageItem> items, IEnumerable<string> paths, ISet<IStorageItem> consumed)
    {
        IStorageFile? storageFile = items.OfType<IStorageFile>().FirstOrDefault();
        string? path = storageFile is null ? null : GetLocalPath(storageFile);
        if (storageFile is null || path is null)
        {
            return false;
        }

        consumed.Add(storageFile);
        if (!RetainEraseArchiveAccess(storageFile))
        {
            return false;
        }

        SetErasePath(path);
        MainTabs.SelectedItem = EraseTab;
        Log(string.Format(System.Globalization.CultureInfo.CurrentCulture, T("dropEraseTarget"), path));
        return true;
    }

    private async Task ApplyDropAndReportAsync(DragEventArgs e, MacDropTarget target)
    {
        try { ApplyDrop(e, target); }
        catch (Exception failure)
        {
            e.DragEffects = DragDropEffects.None;
            e.Handled = true;
            await ReportStorageSelectionFailureAsync(failure);
        }
    }

    private void Window_DragOver(object? sender, DragEventArgs e) => SetDropEffectAndLog(e, MacDropTarget.Auto);
    private async void Window_Drop(object? sender, DragEventArgs e) => await ApplyDropAndReportAsync(e, MacDropTarget.Auto);
    private void CreatePanel_DragOver(object? sender, DragEventArgs e) => SetDropEffectAndLog(e, MacDropTarget.Inputs);
    private async void CreatePanel_Drop(object? sender, DragEventArgs e) => await ApplyDropAndReportAsync(e, MacDropTarget.Inputs);
    private void InputList_DragOver(object? sender, DragEventArgs e) => SetDropEffectAndLog(e, MacDropTarget.Inputs);
    private async void InputList_Drop(object? sender, DragEventArgs e) => await ApplyDropAndReportAsync(e, MacDropTarget.Inputs);
    private void ArchivePathBox_DragOver(object? sender, DragEventArgs e) => SetDropEffectAndLog(e, MacDropTarget.TargetArchive);
    private async void ArchivePathBox_Drop(object? sender, DragEventArgs e) => await ApplyDropAndReportAsync(e, MacDropTarget.TargetArchive);
    private void ExtractPanel_DragOver(object? sender, DragEventArgs e) => SetDropEffectAndLog(e, MacDropTarget.ExtractPanelAuto);

    private async void ExtractPanel_Drop(object? sender, DragEventArgs e) => await ApplyDropAndReportAsync(e, MacDropTarget.ExtractPanelAuto);
    private void ExtractArchiveBox_DragOver(object? sender, DragEventArgs e) => SetDropEffectAndLog(e, MacDropTarget.ExtractArchive);
    private async void ExtractArchiveBox_Drop(object? sender, DragEventArgs e) => await ApplyDropAndReportAsync(e, MacDropTarget.ExtractArchive);
    private void OutputFolderBox_DragOver(object? sender, DragEventArgs e) => SetDropEffectAndLog(e, MacDropTarget.OutputFolder);
    private async void OutputFolderBox_Drop(object? sender, DragEventArgs e) => await ApplyDropAndReportAsync(e, MacDropTarget.OutputFolder);
    private void ErasePanel_DragOver(object? sender, DragEventArgs e) => SetDropEffectAndLog(e, MacDropTarget.EraseTarget);
    private async void ErasePanel_Drop(object? sender, DragEventArgs e) => await ApplyDropAndReportAsync(e, MacDropTarget.EraseTarget);
    private void ErasePathBox_DragOver(object? sender, DragEventArgs e) => SetDropEffectAndLog(e, MacDropTarget.EraseTarget);
    private async void ErasePathBox_Drop(object? sender, DragEventArgs e) => await ApplyDropAndReportAsync(e, MacDropTarget.EraseTarget);
}

internal enum MacDropTarget
{
    Auto,
    Inputs,
    TargetArchive,
    ExtractArchive,
    OutputFolder,
    EraseTarget,
    ExtractPanelAuto,
}
