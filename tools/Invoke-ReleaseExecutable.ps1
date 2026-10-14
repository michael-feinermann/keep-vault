# PowerShell does not always wait for Windows GUI executables. Every release
# acceptance command must observe its own process and real exit status.
function Invoke-ReleaseExecutable {
    param(
        [Parameter(Mandatory = $true)] [string] $Executable,
        [string[]] $Arguments = @(),
        [int] $ExpectedExitCode = 0,
        [ValidateRange(1, 3600)] [int] $TimeoutSeconds = 300
    )
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = [IO.Path]::GetFullPath($Executable)
    $start.WorkingDirectory = [IO.Path]::GetDirectoryName($start.FileName)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw 'The release verification process did not start.' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $timedOut = -not $process.WaitForExit($TimeoutSeconds * 1000)
        if ($timedOut) { $process.Kill($true); $process.WaitForExit() }
        $output = $stdout.GetAwaiter().GetResult()
        $errors = $stderr.GetAwaiter().GetResult()
        if ($output) { Write-Host $output.TrimEnd() }
        if ($errors) { Write-Host $errors.TrimEnd() }
        if ($timedOut) { throw "Release verification exceeded $TimeoutSeconds seconds: $Executable" }
        if ($process.ExitCode -ne $ExpectedExitCode) {
            throw "Release verification exited $($process.ExitCode), expected ${ExpectedExitCode}: $Executable"
        }
    }
    finally { $process.Dispose() }
}
