using Avalonia.Controls;
using KalynaArchiver.Gui;
using KalynaArchiver.Services;

namespace KalynaArchiver;

public sealed partial class MainWindow
{
    private async Task InitializeReleaseAuditAsync()
    {
        if (_releaseAudit is not { } audit || !_integrityTrusted || _disposed) return;
        Title += " · Release audit · öffentliche Testdaten";
        try
        {
            await WarnAsync(IsEnglish
                ? "Release audit: public test data only. This separate process does not accept your normal archives or credentials. Fault cases simulate a fixed failure and cannot publish factors, PDFs or archives. Diagnostic observations are not an overall release verdict."
                : "Release-Audit: ausschließlich öffentliche Testdaten. Dieser eigene Prozess akzeptiert keine normalen Archive oder Zugangsdaten. Fehlerfälle simulieren einen festgelegten Fehler und können keine Faktoren, PDFs oder Archive veröffentlichen. Messungen sind keine Gesamtfreigabe.");
            if (_disposed) return;
            await _releaseAuditInitialization.Start(audit.InitializeAfterTrustedStartup, _lifetimeToken);
            if (_disposed) return;
            _resourcePolicy = new ArchiveOperationPolicy(audit.WorkRoot, audit.WorkRoot);
            DisplayResourcePreferences(); ApplyResourceLanguage();
            CompressionBox.SelectedIndex = 3;
            SelectSuite(EncryptionSuite.ParanoiaCascade);
            DeleteOriginalsBox.IsChecked = false;
            if (!audit.IsFault)
            {
                InputList.Items.Clear(); InputList.Items.Add(audit.SourceRoot);
                ArchivePathBox.Text = audit.ArchivePath;
                SetExtractArchivePathWithoutHint(audit.ArchivePath);
                OutputFolderBox.Text = audit.ExtractionPath;
                CreatePasswordBox.Text = CreatePasswordConfirmBox.Text = ReleaseAuditSession.PublicPassword;
                CreatePinBox.Text = CreatePinConfirmBox.Text = ReleaseAuditSession.PublicPin;
                ExtractPasswordBox.Text = ReleaseAuditSession.PublicPassword;
                ExtractPinBox.Text = ReleaseAuditSession.PublicPin;
            }
            Log("Release audit case: " + audit.CaseId);
            Log("Release audit private public-fixture/evidence directory: " + audit.WorkRoot);
            Log(audit.IsFault
                ? "Controlled negative case: click Generate once. Public synthetic records, real OS routing/locks, no human-capture claim."
                : "Public 256 MiB fixture, level 3. Collect real mouse entropy, click Generate, complete the normal test key-sheet dialog, then click Archive and Extract. Factors are never included in diagnostic JSON.");
            UpdateEntropyStatus(force: true);
            UpdateProtectedOperationControls();
        }
        catch (OperationCanceledException) when (_disposed || _lifetimeToken.IsCancellationRequested) { }
        catch
        {
            await ReportReleaseAuditInitializationFailureAsync();
        }
    }

    private async Task ReportReleaseAuditInitializationFailureAsync()
    {
        if (_disposed || _lifetimeToken.IsCancellationRequested) return;
        Log("Release audit initialization failed. No audit operation or release verdict is available.");
        await ErrorAsync(IsEnglish ? "Release audit initialization failed." : "Die Release-Audit-Vorbereitung ist fehlgeschlagen.");
        if (!_disposed) ApplyReleaseAuditControlRestrictions();
    }

    private bool AuditAllowsOperation(string operation)
    {
        if (_releaseAudit is not { } audit) return true;
        if (!audit.Allows(operation))
        {
            Log("The isolated release-audit process refuses this operation.");
            return false;
        }
        try
        {
            if (_resourcePolicy.Preferences.WorkingDirectory is null)
            {
                // Reset to Auto retains the audit's private work location;
                // all CPU/RAM/I/O/queue decisions remain the selected policy.
                _resourcePolicy = new ArchiveOperationPolicy(audit.WorkRoot, audit.WorkRoot,
                    preferences: _resourcePolicy.Preferences with { WorkingDirectory = audit.WorkRoot });
                DisplayResourcePreferences(); ApplyResourceLanguage();
            }
            if (audit.IsFault) return true;
            // Validate before file-picker, source inspection, credential parse,
            // recovery, or any normal archive execution can inspect foreign input.
            if (operation is "create" or "key-sheet")
                audit.RequirePublicCredentials(CreatePasswordBox.Text, CreatePinBox.Text);
            else if (operation is "extract" or "list" or "recovery")
                audit.RequirePublicCredentials(ExtractPasswordBox.Text, ExtractPinBox.Text);
            if (operation == "create")
                audit.RequirePublicCreation(InputList.Items.OfType<string>().ToArray(), ArchivePathBox.Text ?? string.Empty,
                    EncryptBox.IsChecked == true, DeleteOriginalsBox.IsChecked == true, CompressionBox.SelectedIndex);
            else if (operation is "extract" or "list" or "recovery")
                audit.RequirePublicArchive(ExtractArchiveBox.Text ?? string.Empty,
                    operation == "extract" ? OutputFolderBox.Text ?? string.Empty : null);
            return true;
        }
        catch
        {
            Log("The release audit refused input outside its declared public fixture/credentials.");
            return false;
        }
    }

    private void ApplyReleaseAuditControlRestrictions()
    {
        if (_releaseAudit is not { } audit || !_componentsReady) return;
        bool ready = audit.IsInitialized && !_disposed && Volatile.Read(ref _operationActive) == 0 && _integrityTrusted;
        ErasePanel.IsEnabled = false;
        EraseContainerButton.IsEnabled = false;
        AddFilesButton.IsEnabled = AddFolderButton.IsEnabled = ClearInputsButton.IsEnabled = false;
        BrowseArchiveButton.IsEnabled = BrowseExtractArchiveButton.IsEnabled = BrowseOutputFolderButton.IsEnabled = false;
        ArchivePathBox.IsReadOnly = ExtractArchiveBox.IsReadOnly = OutputFolderBox.IsReadOnly = true;
        WorkingDirectoryBox.IsReadOnly = true;
        ChooseWorkingDirectoryButton.IsEnabled = false;
        CompressionBox.IsEnabled = false;
        EncryptBox.IsEnabled = false;
        if (audit.IsFault) CipherSuiteBox.IsEnabled = false;
        if (!ready || audit.IsFault)
        {
            CreateArchiveButton.IsEnabled = false;
            ExtractPanel.IsEnabled = false;
            ExtractArchiveButton.IsEnabled = ListArchiveButton.IsEnabled = EmergencyRecoveryButton.IsEnabled = false;
            SaveKeySheetButton.IsEnabled = false;
            PrintKeySheetButton.IsEnabled = false;
            DeleteOriginalsBox.IsEnabled = false;
        }
        else
        {
            SaveKeySheetButton.IsEnabled = true;
            PrintKeySheetButton.IsEnabled = true;
            DeleteOriginalsBox.IsEnabled = false;
        }
        if (!ready || audit.FaultConsumed) GeneratePasswordButton.IsEnabled = false;
    }

    private void CompleteReleaseAuditOperation(bool cancelled)
    {
        if (_releaseAudit is not { } audit) return;
        try
        {
            string? receipt = audit.CompleteOperation(_operationReportedSuccess, _operationReportedFailure,
                cancelled,
                _generatedPairReady || !string.IsNullOrEmpty(GeneratedPasswordFirstBox.Text)
                    || !string.IsNullOrEmpty(GeneratedPasswordSecondBox.Text));
            if (receipt is not null) Log("Release audit metadata written after operation cleanup: " + receipt);
        }
        catch
        {
            // Diagnostic export cannot change the underlying archive result.
            // A missing/malformed receipt is unavailable evidence, never PASS.
            Log("Release audit diagnostic export unavailable. No release gate is granted.");
        }
        ApplyReleaseAuditControlRestrictions();
    }
}
