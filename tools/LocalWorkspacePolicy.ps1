function Assert-LocalReleaseWorkspace {
    param([Parameter(Mandatory)][string] $RepositoryRoot)
    $fullPath = [IO.Path]::GetFullPath($RepositoryRoot)
    if ($fullPath -match '(?i)(^|[\\/])OneDrive(?: - [^\\/]*)?([\\/]|$)') {
        throw 'Development and release builds must not run inside OneDrive. Use C:\Dev\Kalyna on this Windows workstation.'
    }
    foreach ($name in @('OneDrive', 'OneDriveConsumer', 'OneDriveCommercial')) {
        $configured = [Environment]::GetEnvironmentVariable($name)
        if (-not [string]::IsNullOrWhiteSpace($configured)) {
            $syncRoot = [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($configured))
            if ($fullPath -ieq $syncRoot -or $fullPath.StartsWith($syncRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Development and release builds must not run inside the configured OneDrive directory.'
            }
        }
    }
}
