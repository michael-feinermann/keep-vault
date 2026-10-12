using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

// A narrow regression probe against the exact loaded product assembly. The
// constructor receives only this process's public synthetic byte array and a
// fake IDisposable. No real key, native RAM lock, GUI, KDF or cipher is touched.
if (args.Length != 3 || (args[0] != "before" && args[0] != "after"))
    throw new ArgumentException("Expected before|after, product DLL, receipt path.");

string variant = args[0];
string artifactPath = Path.GetFullPath(args[1]);
string receiptPath = Path.GetFullPath(args[2]);
string artifactSha256 = HashFile(artifactPath);
Assembly product = Assembly.LoadFrom(artifactPath);
Type ownerType = product.GetType("KalynaArchiver.Services.LockedSensitiveBuffer", throwOnError: true)!;
ConstructorInfo constructor = ownerType.GetConstructor(BindingFlags.Instance | BindingFlags.NonPublic,
    binder: null, [typeof(byte[]), typeof(IDisposable)], modifiers: null)
    ?? throw new InvalidOperationException("Expected internal sensitive-owner constructor is missing.");
PropertyInfo bytesProperty = ownerType.GetProperty("Bytes", BindingFlags.Instance | BindingFlags.Public)
    ?? throw new InvalidOperationException("Expected owner Bytes getter is missing.");
byte[] publicAlias = Enumerable.Range(0, 128).Select(index => (byte)(index * 29 + 7)).ToArray();
var fakeUnlock = new FailsOnceDisposable();
var owner = (IDisposable)constructor.Invoke([publicAlias, fakeUnlock]);
bool initialGetterMatchesCallerAlias = ReferenceEquals(publicAlias, bytesProperty.GetValue(owner));
bool firstDisposeReportedInjectedFailure = false;
try { owner.Dispose(); }
catch (IOException) { firstDisposeReportedInjectedFailure = true; }
bool aliasErasedBeforeFailedUnlockReturn = publicAlias.All(value => value == 0);
bool getterReturnedAliasAfterFailure = false;
bool getterRejectedAfterFailure = false;
try
{
    object? returned = bytesProperty.GetValue(owner);
    getterReturnedAliasAfterFailure = ReferenceEquals(returned, publicAlias);
}
catch (TargetInvocationException failure) when (failure.InnerException is ObjectDisposedException)
{
    getterRejectedAfterFailure = true;
}

owner.Dispose();
bool retryCompleted = fakeUnlock.Attempts == 2 && fakeUnlock.Completed;
bool getterRejectedAfterRetry = false;
try { _ = bytesProperty.GetValue(owner); }
catch (TargetInvocationException failure) when (failure.InnerException is ObjectDisposedException)
{
    getterRejectedAfterRetry = true;
}
owner.Dispose();
bool completedDisposeIsIdempotent = fakeUnlock.Attempts == 2;
bool unchangedProductArtifact = artifactSha256 == HashFile(artifactPath);
bool observedExpectedRegression = initialGetterMatchesCallerAlias
    && firstDisposeReportedInjectedFailure && aliasErasedBeforeFailedUnlockReturn
    && retryCompleted && getterRejectedAfterRetry && completedDisposeIsIdempotent
    && unchangedProductArtifact
    && (variant == "before"
        ? getterReturnedAliasAfterFailure && !getterRejectedAfterFailure
        : !getterReturnedAliasAfterFailure && getterRejectedAfterFailure);
CryptographicOperations.ZeroMemory(publicAlias);

var receipt = new
{
    schemaVersion = 1,
    testId = "security.owner-failed-dispose-before-after",
    variant,
    status = observedExpectedRegression
        ? variant == "before" ? "OLD_SECURITY_FAILURE_REPRODUCED" : "NEW_REGRESSION_PASS"
        : "UNEXPECTED_OBSERVATION",
    securityGatePassed = observedExpectedRegression && variant == "after",
    expectedObservationMatched = observedExpectedRegression,
    createdUtc = DateTimeOffset.UtcNow,
    actualPid = Environment.ProcessId,
    productAssemblyPath = artifactPath,
    productAssemblySha256 = artifactSha256,
    productAssemblyIdentity = product.FullName,
    productArtifactUnchangedDuringExecution = unchangedProductArtifact,
    probeAssemblySha256 = HashFile(Assembly.GetExecutingAssembly().Location),
    framework = RuntimeInformation.FrameworkDescription,
    processArchitecture = RuntimeInformation.ProcessArchitecture.ToString(),
    initialGetterMatchesCallerAlias,
    firstDisposeReportedInjectedFailure,
    aliasErasedBeforeFailedUnlockReturn,
    getterReturnedAliasAfterFailure,
    getterRejectedAfterFailure,
    fakeUnlockAttempts = fakeUnlock.Attempts,
    retryCompleted,
    getterRejectedAfterRetry,
    completedDisposeIsIdempotent,
    scope = "Only LockedSensitiveBuffer ownership after controlled IDisposable failure; public synthetic 128-byte fixture, separate process per DLL; no native RAM lock, secrets, KDF execution, matrix replay, GUI or release approval",
};
Directory.CreateDirectory(Path.GetDirectoryName(receiptPath)!);
File.WriteAllText(receiptPath, JsonSerializer.Serialize(receipt, new JsonSerializerOptions { WriteIndented = true }) + "\n");
Console.WriteLine(JsonSerializer.Serialize(receipt));
return observedExpectedRegression ? 0 : 1;

static string HashFile(string path)
{
    using FileStream input = File.OpenRead(path);
    return Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant();
}

internal sealed class FailsOnceDisposable : IDisposable
{
    internal int Attempts { get; private set; }
    internal bool Completed { get; private set; }
    public void Dispose()
    {
        Attempts++;
        if (Attempts == 1) throw new IOException("Public fixture: simulated first IDisposable failure.");
        Completed = true;
    }
}
