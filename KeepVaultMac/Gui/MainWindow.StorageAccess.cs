using Avalonia.Platform.Storage;
using KalynaArchiver.Gui;

namespace KalynaArchiver;

public sealed partial class MainWindow
{
    private readonly Dictionary<string, MacStorageAccessLease> _inputStorageAccess = new(StringComparer.Ordinal);

    private MacStorageAccessLease? _archiveDestinationAccess;
    private MacStorageAccessLease? _extractArchiveAccess;
    private MacStorageAccessLease? _extractArchiveParentAccess;
    private MacStorageAccessLease? _extractOutputParentAccess;
    private MacStorageAccessLease? _eraseArchiveAccess;
    private MacStorageAccessLease? _eraseArchiveParentAccess;
    private readonly List<MacStorageAccessLease> _pendingStorageDisposals = [];
    private readonly List<IStorageItem> _pendingStorageItemDisposals = [];
    private readonly HashSet<IStorageItem> _disposingStorageItems = new(ReferenceEqualityComparer.Instance);
    private readonly HashSet<MacStorageAccessLease> _disposingStorageLeases = new(ReferenceEqualityComparer.Instance);

    internal bool HandleFileActivation(IStorageFile file) => HandleFileActivation(file, out _);

    internal bool HandleFileActivation(IStorageFile file, out bool consumed)
    {
        consumed = false;
        ArgumentNullException.ThrowIfNull(file);
        string? path = GetLocalPath(file);
        if (_disposed || path is null || !HasArchiveExtension(path))
        {
            return false;
        }

        // From this point acquisition owns every success, refusal and failure
        // path. The caller must not dispose the provider item a second time.
        consumed = true;
        if (!RetainExtractArchiveAccess(file))
        {
            return false;
        }

        if (!File.Exists(path))
        {
            ReleaseStorageAccess(ref _extractArchiveAccess);
            return false;
        }

        SetExtractArchivePath(path);
        MainTabs.SelectedItem = ExtractTab;
        if (!IsVisible)
        {
            Show();
        }

        if (WindowState == Avalonia.Controls.WindowState.Minimized)
        {
            WindowState = Avalonia.Controls.WindowState.Normal;
        }

        Activate();
        Log(string.Format(
            System.Globalization.CultureInfo.CurrentCulture,
            T("finderOpenedArchive"),
            path));
        return true;
    }

    internal bool HasActivationStorageOwnership => RetainedStorageAccess().Any()
        || _pendingStorageDisposals.Count != 0 || _pendingStorageItemDisposals.Count != 0
        || _disposingStorageItems.Count != 0 || _disposingStorageLeases.Count != 0;

    internal bool OwnsActivationStorageItem(IStorageItem item) => IsStorageAccessRetained(item)
        || _pendingStorageDisposals.Any(owner => owner.OwnsItem(item))
        || _pendingStorageItemDisposals.Any(owner => ReferenceEquals(owner, item)) || _disposingStorageItems.Contains(item)
        || _disposingStorageLeases.Any(owner => owner.OwnsItem(item));

    internal void DisposeUnacceptedActivationItem(IStorageItem item)
    {
        if (_pendingStorageItemDisposals.Any(owner => ReferenceEquals(owner, item)))
            throw new ObjectDisposedException(nameof(IStorageItem), "Storage item cleanup must complete before reuse.");
        DisposeOwnedStorageItem(item);
    }

    internal void RetryActivationStorageCleanup()
    {
        MacStorageAccessLease[] owners = [.. _pendingStorageDisposals];
        IStorageItem[] items = [.. _pendingStorageItemDisposals];
        _pendingStorageDisposals.Clear();
        _pendingStorageItemDisposals.Clear();
        List<Exception>? failures = null;
        try { DisposeOwnedStorageAccesses(owners); }
        catch (Exception failure) { (failures ??= []).Add(failure); }
        try { DisposeUnretainedStorageItems(items); }
        catch (Exception failure) { (failures ??= []).Add(failure); }
        if (failures is not null) throw new AggregateException("Activation storage cleanup failed.", failures);
    }

    internal Task ReportFileActivationFailureAsync(Exception failure) => ReportStorageSelectionFailureAsync(failure);

    private int AddInputStorageItems(IEnumerable<IStorageItem> items)
    {
        int added = 0;
        List<Exception>? failures = null;
        var seen = new HashSet<IStorageItem>(ReferenceEqualityComparer.Instance);
        foreach (IStorageItem item in items)
        {
            if (!seen.Add(item)) continue;
            MacStorageAccessLease? next = null;
            bool itemHandled = false;
            try
            {
                string? path = GetLocalPath(item);
                if (path is null)
                {
                    itemHandled = true;
                    DisposeOwnedStorageItem(item);
                    continue;
                }
                itemHandled = true; // TryAcquire owns every refusal/failure path.
                if (!TryAcquireStorageAccess(item, out MacStorageAccessLease acquired)) continue;
                next = acquired;
                if (!File.Exists(path) && !Directory.Exists(path)) continue;

                added += AddInputPaths([path]);
                if (!InputList.Items.OfType<string>().Contains(path, StringComparer.Ordinal)) continue;
                _inputStorageAccess.TryGetValue(path, out MacStorageAccessLease? previous);
                _inputStorageAccess[path] = next;
                next = null; // Transfer before retiring the old owner.
                if (previous is not null) DisposeOwnedStorageAccess(previous);
            }
            catch (Exception failure) { (failures ??= []).Add(failure); }
            finally
            {
                try
                {
                    if (next is not null) DisposeOwnedStorageAccess(next);
                    else if (!itemHandled) DisposeOwnedStorageItem(item);
                }
                catch (Exception failure) { (failures ??= []).Add(failure); }
            }
        }
        if (failures is not null) throw new AggregateException("Input storage ownership update failed.", failures);
        return added;
    }

    private void ClearInputStorageAccess()
    {
        MacStorageAccessLease[] retired = [.. _inputStorageAccess.Values];
        _inputStorageAccess.Clear();
        DisposeOwnedStorageAccesses(retired);
    }

    private bool RetainArchiveDestinationAccess(IStorageFolder folder)
    {
        return ReplaceStorageAccess(ref _archiveDestinationAccess, folder);
    }

    private bool RetainExtractArchiveAccess(IStorageFile file)
    {
        return ReplaceStorageAccess(ref _extractArchiveAccess, file);
    }

    private bool RetainExtractOutputParentAccess(IStorageFolder folder)
    {
        return ReplaceStorageAccess(ref _extractOutputParentAccess, folder);
    }

    private bool RetainEraseArchiveAccess(IStorageFile file)
    {
        return ReplaceStorageAccess(ref _eraseArchiveAccess, file);
    }

    private bool ReplaceStorageAccess(ref MacStorageAccessLease? current, IStorageItem item)
    {
        if (!TryAcquireStorageAccess(item, out MacStorageAccessLease next))
        {
            return false;
        }

        MacStorageAccessLease? previous = current;
        current = next;
        if (previous is not null) DisposeOwnedStorageAccess(previous);
        return true;
    }

    private bool TryAcquireStorageAccess(IStorageItem item, out MacStorageAccessLease lease)
    {
        lease = null!;
        if (_disposingStorageItems.Contains(item) || _disposingStorageLeases.Any(owner => owner.OwnsItem(item))
            || _pendingStorageDisposals.Any(owner => owner.OwnsItem(item))
            || _pendingStorageItemDisposals.Any(owner => ReferenceEquals(owner, item)))
        {
            throw new ObjectDisposedException(nameof(IStorageItem), "Storage item cleanup must complete before reuse.");
        }
        if (_disposed)
        {
            DisposeOwnedStorageItem(item);
            return false;
        }

        MacStorageAccessLease acquired;
        try
        {
            MacStorageAccessLease? existing = RetainedStorageAccess()
                .FirstOrDefault(owner => owner.OwnsItem(item));
            if (existing is not null)
            {
                lease = existing;
                return true;
            }
            acquired = MacStorageAccessLease.Acquire(item);
        }
        catch (Exception exception)
        {
            try { DisposeOwnedStorageItem(item); }
            catch (Exception cleanup)
            {
                throw new AggregateException("Storage acquisition and item cleanup failed.", exception, cleanup);
            }
            if (exception is not (UnauthorizedAccessException or InvalidOperationException or NotSupportedException)) throw;
            Log($"Security-scoped URL lease failed: {exception.Message}");
            _ = ErrorAsync(T("sandboxLeaseFailed"));
            return false;
        }
        // A provider callback can close the window during acquisition.
        if (_disposed)
        {
            DisposeOwnedStorageAccess(acquired);
            return false;
        }
        lease = acquired;
        return true;
    }

    private MacStorageAccessLease? MatchCurrentStorageFile(ref MacStorageAccessLease? current, string path)
    {
        MacStorageAccessLease? captured = current;
        return !_disposed && captured is not null && StorageItemNamesPath(captured.Item, path)
            && !_disposed && ReferenceEquals(current, captured) ? captured : null;
    }

    private MacStorageAccessLease? MatchCurrentStorageParent(ref MacStorageAccessLease? current, string path)
    {
        MacStorageAccessLease? captured = current;
        return !_disposed && captured is not null && StorageFolderIsParentOf(captured, path)
            && !_disposed && ReferenceEquals(current, captured) ? captured : null;
    }

    private MacSecurityScopedResourceLease? AcquireTransientExtractAccess(string archivePath)
    {
        MacStorageAccessLease? access = MatchCurrentStorageFile(ref _extractArchiveAccess, archivePath);
        int binding = 1;
        if (access is null) { access = MatchCurrentStorageParent(ref _extractArchiveParentAccess, archivePath); binding = 2; }
        if (access is null) { access = MatchCurrentStorageParent(ref _extractOutputParentAccess, archivePath); binding = 3; }
        if (access is null) return null;
        try
        {
            MacSecurityScopedResourceLease transient = MacSecurityScopedResourceLease.Acquire(access.Item);
            bool sameBinding = binding switch
            {
                1 => ReferenceEquals(_extractArchiveAccess, access),
                2 => ReferenceEquals(_extractArchiveParentAccess, access),
                _ => ReferenceEquals(_extractOutputParentAccess, access),
            };
            if (_disposed || !sameBinding)
            {
                transient.Dispose();
                return null;
            }
            return transient;
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException
            or InvalidOperationException or NotSupportedException)
        {
            Log($"Transient security-scoped URL lease failed: {exception.Message}");
            return null;
        }
    }

    private MacSecurityScopedResourceLease AcquireTransientEraseAccess(string archivePath)
    {
        MacStorageAccessLease? access = MatchCurrentStorageParent(ref _eraseArchiveParentAccess, archivePath);
        if (access is null) throw new UnauthorizedAccessException(T("sandboxFolderAccessRequired"));
        MacSecurityScopedResourceLease transient = MacSecurityScopedResourceLease.Acquire(access.Item);
        if (_disposed || !ReferenceEquals(_eraseArchiveParentAccess, access))
        {
            transient.Dispose();
            throw new UnauthorizedAccessException(T("sandboxFolderAccessRequired"));
        }
        return transient;
    }

    private void ReleaseArchiveDestinationAccessIfMismatched(string archivePath)
    {
        MacStorageAccessLease? captured = _archiveDestinationAccess;
        if (!_disposed && captured is not null && !StorageFolderIsParentOf(captured, archivePath)
            && !_disposed && ReferenceEquals(_archiveDestinationAccess, captured))
        {
            _archiveDestinationAccess = null;
            DisposeOwnedStorageAccess(captured);
        }
    }

    private void ReleaseExtractAccessIfMismatched(string archivePath)
        => ReleaseFileAndParentAccessIfMismatched(ref _extractArchiveAccess, ref _extractArchiveParentAccess, archivePath);

    private void ReleaseFileAndParentAccessIfMismatched(
        ref MacStorageAccessLease? archiveAccess, ref MacStorageAccessLease? parentAccess, string archivePath)
    {
        MacStorageAccessLease? archive = archiveAccess, parent = parentAccess;
        List<MacStorageAccessLease> retired = [];
        List<Exception>? failures = null;
        try
        {
            if (!_disposed && archive is not null && ReferenceEquals(archiveAccess, archive)
                && !StorageItemNamesPath(archive.Item, archivePath)
                && !_disposed && ReferenceEquals(archiveAccess, archive))
            {
                archiveAccess = null;
                retired.Add(archive);
            }
        }
        catch (Exception failure) { (failures ??= []).Add(failure); }
        try
        {
            if (!_disposed && parent is not null && ReferenceEquals(parentAccess, parent)
                && !StorageFolderIsParentOf(parent, archivePath)
                && !_disposed && ReferenceEquals(parentAccess, parent))
            {
                parentAccess = null;
                retired.Add(parent);
            }
        }
        catch (Exception failure) { (failures ??= []).Add(failure); }
        finally
        {
            // A later provider Path failure must not lose an already retired
            // owner, and one failed probe must not skip the independent probe.
            try { DisposeOwnedStorageAccesses(retired); }
            catch (Exception failure) { (failures ??= []).Add(failure); }
        }
        if (failures is not null) throw new AggregateException("Storage path validation and retirement failed.", failures);
    }

    private void ReleaseExtractOutputAccessIfMismatched(string outputPath)
    {
        MacStorageAccessLease? captured = _extractOutputParentAccess;
        if (!_disposed && captured is not null && !StorageFolderIsParentOf(captured, outputPath)
            && !_disposed && ReferenceEquals(_extractOutputParentAccess, captured))
        {
            _extractOutputParentAccess = null;
            DisposeOwnedStorageAccess(captured);
        }
    }

    private void ReleaseEraseAccessIfMismatched(string archivePath)
        => ReleaseFileAndParentAccessIfMismatched(ref _eraseArchiveAccess, ref _eraseArchiveParentAccess, archivePath);

    private async Task<bool> EnsureArchiveDestinationAccessAsync(string archivePath)
    {
        if (MatchCurrentStorageParent(ref _archiveDestinationAccess, archivePath) is not null)
        {
            return true;
        }

        IStorageFolder? folder = await RequestExactParentFolderAccessAsync(
            archivePath,
            T("chooseArchiveDestinationFolderDialog"),
            _archiveDestinationAccess);
        if (folder is null)
        {
            return false;
        }

        return RetainArchiveDestinationAccess(folder);
    }

    private async Task<bool> EnsureExtractArchiveParentAccessAsync(string archivePath)
    {
        if (MatchCurrentStorageParent(ref _extractArchiveParentAccess, archivePath) is not null
            || MatchCurrentStorageParent(ref _extractOutputParentAccess, archivePath) is not null)
        {
            return true;
        }

        IStorageFolder? folder = await RequestExactParentFolderAccessAsync(
            archivePath,
            T("chooseArchiveSidecarFolderDialog"),
            _extractArchiveAccess);
        if (folder is null)
        {
            return false;
        }

        return ReplaceStorageAccess(ref _extractArchiveParentAccess, folder);
    }

    private async Task<bool> EnsureExtractOutputParentAccessAsync(string outputPath)
    {
        if (MatchCurrentStorageParent(ref _extractOutputParentAccess, outputPath) is not null
            || MatchCurrentStorageParent(ref _extractArchiveParentAccess, outputPath) is not null)
        {
            return true;
        }

        IStorageFolder? folder = await RequestExactParentFolderAccessAsync(
            outputPath,
            T("chooseOutputParentDialog"),
            _extractOutputParentAccess);
        if (folder is null)
        {
            return false;
        }

        return RetainExtractOutputParentAccess(folder);
    }

    private async Task<bool> EnsureEraseArchiveParentAccessAsync(string archivePath)
    {
        if (MatchCurrentStorageParent(ref _eraseArchiveParentAccess, archivePath) is not null)
        {
            return true;
        }

        IStorageFolder? folder = await RequestExactParentFolderAccessAsync(
            archivePath,
            T("chooseEraseSidecarFolderDialog"),
            _eraseArchiveAccess);
        if (folder is null)
        {
            return false;
        }

        return ReplaceStorageAccess(ref _eraseArchiveParentAccess, folder);
    }

    private async Task<IStorageFolder?> RequestExactParentFolderAccessAsync(
        string childPath,
        string title,
        MacStorageAccessLease? suggestedAccess)
    {
        if (_disposed) return null;
        string? normalizedChild = NormalizeLocalPath(childPath);
        string? expectedParent = normalizedChild is null ? null : Path.GetDirectoryName(normalizedChild);
        if (string.IsNullOrWhiteSpace(expectedParent))
        {
            await WarnAsync(T("sandboxParentUnavailable"));
            return null;
        }

        IReadOnlyList<IStorageFolder> folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = title,
            AllowMultiple = false,
            SuggestedStartLocation = suggestedAccess?.Item as IStorageFolder,
        });
        IStorageFolder? selected = folders.FirstOrDefault();
        bool selectedCleanupStarted = false;
        try
        {
            DisposeUnretainedStorageItems(folders.Skip(1).Where(extra => !ReferenceEquals(extra, selected)));
            if (selected is null)
            {
                if (!_disposed) await WarnAsync(T("sandboxFolderAccessRequired"));
                return null;
            }

            string? selectedPath = GetLocalPath(selected);
            if (_disposed || !PathsNameSameDirectory(selectedPath, expectedParent))
            {
                selectedCleanupStarted = true;
                DisposeOwnedStorageItem(selected);
                if (!_disposed) await WarnAsync(string.Format(
                    System.Globalization.CultureInfo.CurrentCulture,
                    T("sandboxWrongFolder"),
                    expectedParent));
                return null;
            }
            return selected;
        }
        catch (Exception failure)
        {
            if (selected is not null && !selectedCleanupStarted)
            {
                try { DisposeOwnedStorageItem(selected); }
                catch (Exception cleanup)
                {
                    throw new AggregateException("Folder selection and item cleanup failed.", failure, cleanup);
                }
            }
            throw;
        }
    }

    private async Task ApplyStoragePickerSelectionAsync<T>(
        IReadOnlyList<T> items,
        Func<T, bool> retain,
        Action<string> render,
        Func<string, bool>? allowedPath = null,
        string? invalidTypeMessage = null) where T : class, IStorageItem
    {
        T? selected = items.FirstOrDefault();
        bool selectedHandled = false;
        List<Exception>? failures = null;
        try
        {
            DisposeUnretainedStorageItems(items.Skip(1).Where(extra => !ReferenceEquals(extra, selected)));
            if (selected is null) return;
            string? path = GetLocalPath(selected);
            if (_disposed || path is null || allowedPath?.Invoke(path) == false)
            {
                selectedHandled = true;
                DisposeOwnedStorageItem(selected);
                if (!_disposed && path is not null && invalidTypeMessage is not null)
                    await WarnAsync(invalidTypeMessage);
                return;
            }
            selectedHandled = true; // Retain consumes every acquisition path.
            try { retain(selected); }
            catch (Exception failure) { (failures ??= []).Add(failure); }
            // Old-owner cleanup can fail after the new field is already bound.
            // Keep its actual path visible and preserve both failures if render
            // independently fails as well.
            if (!_disposed && IsStorageAccessRetained(selected))
            {
                try { render(path); }
                catch (Exception failure) { (failures ??= []).Add(failure); }
            }
        }
        catch (Exception failure) { (failures ??= []).Add(failure); }
        finally
        {
            if (selected is not null && !selectedHandled)
            {
                try { DisposeOwnedStorageItem(selected); }
                catch (Exception failure) { (failures ??= []).Add(failure); }
            }
        }
        if (failures is not null) throw new AggregateException("Storage selection ownership update failed.", failures);
    }

    private async Task<bool> TryReleaseStoragePathAccessAndReportAsync(Action release)
    {
        try { release(); return true; }
        catch (Exception failure)
        {
            await ReportStorageSelectionFailureAsync(failure);
            return false;
        }
    }

    private async Task ReportStorageSelectionFailureAsync(Exception failure)
    {
        if (_disposed) return;
        Log(failure.ToString());
        await ErrorAsync(failure.Message);
    }

    private void DisposeStorageAccess()
    {
        MacStorageAccessLease?[] retained =
        [
            _resourceWorkingAccess, _archiveDestinationAccess, _extractArchiveAccess,
            _extractArchiveParentAccess, _extractOutputParentAccess, _eraseArchiveAccess,
            _eraseArchiveParentAccess, .. _inputStorageAccess.Values,
            .. _pendingStorageDisposals,
        ];
        IStorageItem[] retainedItems = [.. _pendingStorageItemDisposals];
        // No failed cleanup may leave a disposed lease available to an operation.
        _resourceWorkingAccess = null;
        _archiveDestinationAccess = null;
        _extractArchiveAccess = null;
        _extractArchiveParentAccess = null;
        _extractOutputParentAccess = null;
        _eraseArchiveAccess = null;
        _eraseArchiveParentAccess = null;
        _inputStorageAccess.Clear();
        _pendingStorageDisposals.Clear();
        _pendingStorageItemDisposals.Clear();

        List<Exception>? failures = null;
        try { DisposeOwnedStorageAccesses(retained.OfType<MacStorageAccessLease>()); }
        catch (Exception failure) { (failures ??= []).Add(failure); }
        try { DisposeUnretainedStorageItems(retainedItems); }
        catch (Exception failure) { (failures ??= []).Add(failure); }
        if (failures is not null)
        {
            throw new AggregateException("Window storage cleanup failed.", failures);
        }
    }

    private IEnumerable<MacStorageAccessLease> RetainedStorageAccess() => new[]
    {
        _resourceWorkingAccess, _archiveDestinationAccess, _extractArchiveAccess,
        _extractArchiveParentAccess, _extractOutputParentAccess, _eraseArchiveAccess,
        _eraseArchiveParentAccess,
    }.OfType<MacStorageAccessLease>().Concat(_inputStorageAccess.Values).Distinct();

    private void ReleaseStorageAccess(ref MacStorageAccessLease? current)
    {
        MacStorageAccessLease? previous = current;
        current = null;
        if (previous is not null) DisposeOwnedStorageAccess(previous);
    }

    private void DisposeOwnedStorageAccess(MacStorageAccessLease lease)
    {
        if (RetainedStorageAccess().Any(owner => ReferenceEquals(owner, lease))) return;
        if (!_disposingStorageLeases.Add(lease)) return;
        try
        {
            lease.Dispose();
            _pendingStorageDisposals.Remove(lease);
        }
        catch
        {
            if (!_pendingStorageDisposals.Contains(lease)) _pendingStorageDisposals.Add(lease);
            throw;
        }
        finally { _disposingStorageLeases.Remove(lease); }
    }

    private void DisposeOwnedStorageAccesses(IEnumerable<MacStorageAccessLease> leases)
    {
        List<Exception>? failures = null;
        foreach (MacStorageAccessLease lease in leases.Distinct())
        {
            try { DisposeOwnedStorageAccess(lease); }
            catch (Exception failure) { (failures ??= []).Add(failure); }
        }
        if (failures is not null) throw new AggregateException("Owned storage cleanup failed.", failures);
    }

    private bool IsStorageAccessRetained(IStorageItem item)
    {
        return RetainedStorageAccess().Any(owner => owner.OwnsItem(item));
    }

    private void DisposeOwnedStorageItem(IStorageItem item)
    {
        if (IsStorageAccessRetained(item) || _pendingStorageDisposals.Any(owner => owner.OwnsItem(item))
            || _disposingStorageLeases.Any(owner => owner.OwnsItem(item))) return;
        if (!_disposingStorageItems.Add(item)) return;
        try
        {
            item.Dispose();
            _pendingStorageItemDisposals.RemoveAll(owner => ReferenceEquals(owner, item));
        }
        catch
        {
            if (!_pendingStorageItemDisposals.Any(owner => ReferenceEquals(owner, item)))
                _pendingStorageItemDisposals.Add(item);
            throw;
        }
        finally { _disposingStorageItems.Remove(item); }
    }

    private void DisposeUnretainedStorageItems(IEnumerable<IStorageItem> items)
    {
        List<Exception>? failures = null;
        var seen = new HashSet<IStorageItem>(ReferenceEqualityComparer.Instance);
        foreach (IStorageItem item in items)
        {
            if (!seen.Add(item)) continue;
            try { DisposeOwnedStorageItem(item); }
            catch (Exception failure) { (failures ??= []).Add(failure); }
        }
        if (failures is not null) throw new AggregateException("Selected storage item cleanup failed.", failures);
    }

    private static bool StorageItemNamesPath(IStorageItem? item, string path)
    {
        return item is not null && PathsNameSameItem(GetLocalPath(item), NormalizeLocalPath(path));
    }

    private static bool StorageFolderIsParentOf(MacStorageAccessLease? access, string childPath)
    {
        string? normalizedChild = NormalizeLocalPath(childPath);
        string? parent = normalizedChild is null ? null : Path.GetDirectoryName(normalizedChild);
        return access?.Item is IStorageFolder folder
            && PathsNameSameDirectory(GetLocalPath(folder), parent);
    }

    private static bool PathsNameSameDirectory(string? left, string? right)
    {
        string? normalizedLeft = NormalizeLocalPath(left)?.TrimEnd(Path.DirectorySeparatorChar);
        string? normalizedRight = NormalizeLocalPath(right)?.TrimEnd(Path.DirectorySeparatorChar);
        return normalizedLeft is not null
            && normalizedRight is not null
            && string.Equals(normalizedLeft, normalizedRight, StringComparison.Ordinal);
    }

    private static bool PathsNameSameItem(string? left, string? right)
    {
        return left is not null
            && right is not null
            && string.Equals(left, right, StringComparison.Ordinal);
    }

    private static string? GetLocalPath(IStorageItem item)
    {
        try
        {
            return NormalizeLocalPath(item.TryGetLocalPath());
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or NotSupportedException)
        {
            return null;
        }
    }

    private static string? NormalizeLocalPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        try
        {
            return Path.GetFullPath(path).Normalize(System.Text.NormalizationForm.FormC);
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or NotSupportedException)
        {
            return null;
        }
    }
}
