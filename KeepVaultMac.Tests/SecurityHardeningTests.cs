using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using KalynaArchiver.Services;

internal static class SecurityHardeningTests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new(
            "security.secure-memory-unlock-accounting",
            "mlock rollback and failed munlock preserve exact secure-memory accounting",
            TestSecureMemoryUnlockFailureAsync,
            TestResource.ProcessGlobal,
            "Security"),
        new(
            "security.composite-secret-cleanup",
            "composite secret owners erase all bytes, aggregate failures and retain failed locks for retry",
            TestCompositeSecretCleanupAsync,
            TestResource.ProcessGlobal,
            "Security"),
        new(
            "security.production-secret-cleanup-faults",
            "early, middle and last unlock failures in v12 KDF and authenticator cleanup",
            TestProductionSecretCleanupFaultsAsync,
            TestResource.ProcessGlobal,
            "Security"),
        new(
            "security.container-worker-multifailure",
            "parallel container workers preserve every failure in deterministic worker order",
            TestContainerWorkerMultiFailureAsync,
            TestResource.Light,
            "Security"),
        new(
            "security.authenticator-worker-multifailure",
            "parallel authenticator workers preserve every failure in deterministic leaf order",
            TestAuthenticatorWorkerMultiFailureAsync,
            TestResource.Light,
            "Security"),
        new(
            "security.extraction-parent-no-side-effects",
            "rejected extraction parents create no directory through missing or symlinked ancestors",
            TestExtractionParentNoSideEffectsAsync,
            TestResource.Light,
            "Security"),
        new(
            "recovery.manifest-json-preflight",
            "KPAR2 JSON preflight enforces geometry, token, depth, string and list caps before materialization",
            TestRecoveryManifestJsonPreflightAsync,
            TestResource.Light,
            "Recovery"),
        new(
            "zpaq.process-resource-limits",
            "ZPAQ wall, CPU, RSS and process-count limits",
            TestZpaqProcessResourceLimitsAsync,
            TestResource.ZpaqGlobal,
            "ZPAQ"),
        new(
            "zpaq.fail-fast-error-preservation",
            "ZPAQ fail-fast preserves primary and cleanup failures",
            TestZpaqFailFastErrorPreservationAsync,
            TestResource.ZpaqGlobal,
            "ZPAQ"),
        new(
            "zpaq.sync-consumer-fail-fast",
            "synchronous streaming-consumer failure kills and joins the ZPAQ process tree",
            TestZpaqSynchronousConsumerFailureAsync,
            TestResource.ZpaqGlobal,
            "ZPAQ"),
        new(
            "zpaq.native-hardening-selftests",
            "native ZPAQ rejects stdio, thread, semaphore, root and descriptor-output fault seams",
            TestNativeZpaqHardeningSelfTestsAsync,
            TestResource.ZpaqGlobal,
            "ZPAQ"),
        new(
            "zpaq.three-file-commit-binding",
            "ZPAQ archive and dual-manifest commit identity binding",
            TestPlainArchiveCommitBindingAsync,
            TestResource.ZpaqGlobal,
            "ZPAQ"),
        new(
            "packaging.keychain-secret-not-in-argv",
            "hybrid wrapping key never enters argv, logs, environment or a plaintext file",
            TestKeychainWrappingKeyHelperAsync,
            TestResource.Light,
            "Packaging"),
    ];

    private static Task TestSecureMemoryUnlockFailureAsync()
    {
        if (!OperatingSystem.IsMacOS())
        {
            throw new PlatformNotSupportedException("The v12 release gate currently targets macOS only.");
        }

        long baselineBytes = SecureMemory.LockedBytesForTests;
        long baselineAllocations = SecureMemory.LockedAllocationsForTests;
        int baselineRetainedRollbacks = SecureMemory.RetainedFailedLockRollbacksForTests;
        byte[] failedLockBuffer = new byte[checked(Environment.SystemPageSize * 4)];
        byte[] failedRollbackBuffer = new byte[checked(Environment.SystemPageSize * 4)];
        LockedSensitiveBuffer? buffer = null;
        byte[]? bytes = null;
        int attemptedUnlocks = 0;
        try
        {
            int attemptedLocks = 0;
            int rollbackUnlocks = 0;
            SecureMemory.MacMemoryLockOverrideForTests = (_, _) =>
            {
                if (Interlocked.Increment(ref attemptedLocks) == 1)
                {
                    return 0;
                }

                Marshal.SetLastPInvokeError(12);
                return -1;
            };
            SecureMemory.MacMemoryUnlockOverrideForTests = (_, _) =>
            {
                Interlocked.Increment(ref rollbackUnlocks);
                return 0;
            };
            CryptographicException? lockFailure = CaptureThrows<CryptographicException>(
                () => SecureMemory.TryLock(failedLockBuffer));
            Require(lockFailure is not null, "A partial mlock failure was reported as success.");
            Require(attemptedLocks >= 2 && rollbackUnlocks >= 1, "The partial mlock rollback seam did not acquire and release a page.");
            Require(SecureMemory.LockedBytesForTests == baselineBytes, "A fully rolled-back mlock failure leaked locked-byte accounting.");
            Require(SecureMemory.LockedAllocationsForTests == baselineAllocations, "A fully rolled-back mlock failure leaked allocation accounting.");

            failedRollbackBuffer.AsSpan().Fill(0xA5);
            attemptedLocks = 0;
            SecureMemory.MacMemoryLockOverrideForTests = (_, _) =>
            {
                if (Interlocked.Increment(ref attemptedLocks) == 1)
                {
                    return 0;
                }

                Marshal.SetLastPInvokeError(12);
                return -1;
            };
            SecureMemory.MacMemoryUnlockOverrideForTests = (_, _) =>
            {
                Marshal.SetLastPInvokeError(5);
                return -1;
            };
            CryptographicException? rollbackFailure = CaptureThrows<CryptographicException>(
                () => SecureMemory.TryLock(failedRollbackBuffer));
            Require(rollbackFailure is not null, "A failed partial-lock rollback was reported as success.");
            Require(
                failedRollbackBuffer.AsSpan().IndexOfAnyExcept((byte)0) < 0,
                "A buffer whose partial-lock rollback failed was not erased.");
            Require(
                SecureMemory.RetainedFailedLockRollbacksForTests == baselineRetainedRollbacks + 1,
                "An unreachable partial-lock rollback was not retained for a safe retry.");
            Require(SecureMemory.LockedBytesForTests > baselineBytes, "A failed partial-lock rollback disappeared from locked-byte accounting.");
            Require(SecureMemory.LockedAllocationsForTests == baselineAllocations + 1, "A failed partial-lock rollback disappeared from allocation accounting.");

            SecureMemory.MacMemoryUnlockOverrideForTests = (_, _) => 0;
            SecureMemory.RetryRetainedFailedLockRollbacksForTests();
            Require(
                SecureMemory.RetainedFailedLockRollbacksForTests == baselineRetainedRollbacks,
                "A successful retained-lock retry did not release its retained object.");
            Require(SecureMemory.LockedBytesForTests == baselineBytes, "A successful retained-lock retry did not restore locked-byte accounting.");
            Require(SecureMemory.LockedAllocationsForTests == baselineAllocations, "A successful retained-lock retry did not restore allocation accounting.");

            SecureMemory.MacMemoryLockOverrideForTests = null;
            SecureMemory.MacMemoryUnlockOverrideForTests = null;
            buffer = LockedSensitiveBuffer.Create(checked(Environment.SystemPageSize * 4));
            bytes = buffer.Bytes;
            bytes.AsSpan().Fill(0xA5);
            SecureMemory.MacMemoryUnlockOverrideForTests = (_, _) =>
            {
                Interlocked.Increment(ref attemptedUnlocks);
                Marshal.SetLastPInvokeError(5);
                return -1;
            };

            CryptographicException? failure = CaptureThrows<CryptographicException>(buffer.Dispose);
            Require(failure is not null, "A failed munlock was reported as a successful disposal.");
            Require(attemptedUnlocks > 0, "The munlock failure seam did not cover an OS-owned page.");
            Require(bytes.AsSpan().IndexOfAnyExcept((byte)0) < 0, "The secret buffer was not erased before reporting munlock failure.");
            Require(
                SecureMemory.LockedBytesForTests > baselineBytes,
                "A page that failed munlock disappeared from locked-byte accounting.");
            Require(
                SecureMemory.LockedAllocationsForTests == baselineAllocations + 1,
                "A buffer that failed munlock disappeared from locked-allocation accounting.");

            SecureMemory.MacMemoryUnlockOverrideForTests = null;
            buffer.Dispose();
            buffer = null;
            Require(
                SecureMemory.LockedBytesForTests == baselineBytes,
                "A successful munlock retry did not restore locked-byte accounting.");
            Require(
                SecureMemory.LockedAllocationsForTests == baselineAllocations,
                "A successful munlock retry did not restore locked-allocation accounting.");
        }
        finally
        {
            SecureMemory.MacMemoryLockOverrideForTests = null;
            SecureMemory.MacMemoryUnlockOverrideForTests = null;
            if (buffer is not null)
            {
                buffer.Dispose();
            }
            if (bytes is not null)
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
            CryptographicOperations.ZeroMemory(failedLockBuffer);
            CryptographicOperations.ZeroMemory(failedRollbackBuffer);
        }

        return Task.CompletedTask;
    }

    private static Task TestCompositeSecretCleanupAsync()
    {
        if (!OperatingSystem.IsMacOS())
        {
            throw new PlatformNotSupportedException("The v12 release gate currently targets macOS only.");
        }

        int disposeAttempts = 0;
        var firstFailure = new CryptographicException("first-cleanup-sentinel");
        var lastFailure = new CryptographicException("last-cleanup-sentinel");
        AggregateException independentFailure = CaptureThrows<AggregateException>(
            () => SecureMemory.DisposeAll(
                new TestDisposable(() =>
                {
                    disposeAttempts++;
                    throw firstFailure;
                }),
                new TestDisposable(() => disposeAttempts++),
                new TestDisposable(() =>
                {
                    disposeAttempts++;
                    throw lastFailure;
                })))
            ?? throw new InvalidOperationException("Independent cleanup failures were reported as success.");
        Require(disposeAttempts == 3, "A cleanup failure prevented a later resource from being disposed.");
        Exception[] independentErrors = independentFailure.Flatten().InnerExceptions.ToArray();
        Require(independentErrors.Any(error => ReferenceEquals(error, firstFailure)), "The first cleanup exception identity was lost.");
        Require(independentErrors.Any(error => ReferenceEquals(error, lastFailure)), "The last cleanup exception identity was lost.");

        int pageSizedBuffer = checked(Environment.SystemPageSize * 2);
        VerifyCompositeCleanup(
            "LockedSensitiveBuffer group",
            () =>
            {
                var first = LockedSensitiveBuffer.Create(pageSizedBuffer);
                var second = LockedSensitiveBuffer.Create(pageSizedBuffer);
                var third = LockedSensitiveBuffer.Create(pageSizedBuffer);
                byte[][] bytes = [first.Bytes, second.Bytes, third.Bytes];
                return new CompositeSecretFixture(
                    () => SecureMemory.ZeroAndDisposeAll(first, second, third),
                    bytes);
            });

        VerifyCompositeCleanup(
            "RoleKeyMaterial",
            () =>
            {
                var encryption = LockedSensitiveBuffer.Create(pageSizedBuffer);
                var sha3 = LockedSensitiveBuffer.Create(pageSizedBuffer);
                var skein = LockedSensitiveBuffer.Create(pageSizedBuffer);
                var material = new RoleKeyMaterial(encryption, sha3, skein);
                return new CompositeSecretFixture(
                    material.Dispose,
                    [encryption.Bytes, sha3.Bytes, skein.Bytes]);
            });

        VerifyCompositeCleanup(
            "ContainerChunkSlot",
            () =>
            {
                var slot = new KalynaContainerService.ContainerChunkSlot(
                    pageSizedBuffer,
                    pageSizedBuffer,
                    pageSizedBuffer);
                return new CompositeSecretFixture(
                    slot.Dispose,
                    [slot.Input, slot.Output, slot.Counter, slot.Tag]);
            });

        VerifyCompositeCleanup(
            "SuiteKeyMaterial",
            () =>
            {
                EncryptionSuiteParameters parameters = EncryptionSuiteCatalog.Get(EncryptionSuite.Aes256);
                byte[] derived = new byte[parameters.DerivedKeyBytes];
                derived.AsSpan().Fill(0x5A);
                KalynaContainerService.SuiteKeyMaterial material;
                try
                {
                    material = KalynaContainerService.SuiteKeyMaterial.Create(derived, parameters);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(derived);
                }

                return new CompositeSecretFixture(
                    material.Dispose,
                    [material.EncryptionKey, material.Sha3MacKey, material.SkeinMacKey]);
            });

        return Task.CompletedTask;
    }

    private static void VerifyCompositeCleanup(
        string label,
        Func<CompositeSecretFixture> createFixture)
    {
        long baselineBytes = SecureMemory.LockedBytesForTests;
        long baselineAllocations = SecureMemory.LockedAllocationsForTests;
        int baselineRetained = SecureMemory.RetainedFailedLockRollbacksForTests;
        CompositeSecretFixture fixture = createFixture();
        int unlockAttempts = 0;
        bool allZeroBeforeFirstUnlock = false;
        try
        {
            foreach (byte[] bytes in fixture.Buffers)
            {
                bytes.AsSpan().Fill(0xA5);
            }

            SecureMemory.MacMemoryUnlockOverrideForTests = (_, _) =>
            {
                if (Interlocked.Increment(ref unlockAttempts) == 1)
                {
                    allZeroBeforeFirstUnlock = fixture.Buffers.All(
                        bytes => bytes.AsSpan().IndexOfAnyExcept((byte)0) < 0);
                    Marshal.SetLastPInvokeError(5);
                    return -1;
                }

                return 0;
            };

            AggregateException failure = CaptureThrows<AggregateException>(fixture.Cleanup)
                ?? throw new InvalidOperationException($"{label}: a failed unlock was reported as success.");
            Require(
                ContainsException<CryptographicException>(failure),
                $"{label}: the OS unlock failure was lost from the aggregate.");
            Require(unlockAttempts > 0, $"{label}: the failure seam did not reach an OS-owned page.");
            Require(allZeroBeforeFirstUnlock, $"{label}: a secret remained nonzero when the first unlock began.");
            Require(
                fixture.Buffers.All(bytes => bytes.AsSpan().IndexOfAnyExcept((byte)0) < 0),
                $"{label}: not every secret buffer was erased after cleanup failure.");
            Require(
                SecureMemory.RetainedFailedLockRollbacksForTests > baselineRetained,
                $"{label}: the failed lock was not retained for retry.");
            Require(
                SecureMemory.LockedAllocationsForTests > baselineAllocations,
                $"{label}: the failed lock disappeared from allocation accounting.");

            SecureMemory.MacMemoryUnlockOverrideForTests = null;
            fixture.Cleanup();
            SecureMemory.RetryRetainedFailedLockRollbacksForTests();
            Require(
                SecureMemory.RetainedFailedLockRollbacksForTests == baselineRetained,
                $"{label}: a successful retry did not release the retained lock.");
            Require(
                SecureMemory.LockedBytesForTests == baselineBytes,
                $"{label}: a successful retry did not restore byte accounting.");
            Require(
                SecureMemory.LockedAllocationsForTests == baselineAllocations,
                $"{label}: a successful retry did not restore allocation accounting.");
        }
        finally
        {
            SecureMemory.MacMemoryUnlockOverrideForTests = null;
            try
            {
                fixture.Cleanup();
            }
            finally
            {
                SecureMemory.RetryRetainedFailedLockRollbacksForTests();
                foreach (byte[] bytes in fixture.Buffers)
                {
                    CryptographicOperations.ZeroMemory(bytes);
                }
            }
        }
    }

    private static async Task TestProductionSecretCleanupFaultsAsync()
    {
        if (!OperatingSystem.IsMacOS())
        {
            throw new PlatformNotSupportedException("The v12 release gate currently targets macOS only.");
        }

        byte[] factorA = Enumerable.Repeat((byte)0xA5, ContainerKeyDerivation.FactorBytes).ToArray();
        byte[] factorB = Enumerable.Repeat((byte)0x5A, ContainerKeyDerivation.FactorBytes).ToArray();
        byte[] sha3Destination = Enumerable.Repeat((byte)0xCC, V12MasterKdf.CredentialHashBytes).ToArray();
        byte[] skeinDestination = Enumerable.Repeat((byte)0xDD, V12MasterKdf.CredentialHashBytes).ToArray();
        byte[] ciphertext = RandomNumberGenerator.GetBytes(4096);
        byte[] prefix = "v12-cleanup-auth-prefix"u8.ToArray();
        byte[] sha3MacKey = RandomNumberGenerator.GetBytes(64);
        byte[] skeinMacKey = RandomNumberGenerator.GetBytes(128);
        try
        {
            await VerifyProductionCleanupFailureAsync(
                "SHA3 credential cleanup, first buffer",
                failAtBufferOrdinal: 1,
                expectedBufferDisposals: 4,
                configureCleanupSeam: callback => V12MasterKdf.BeforeCredentialCleanupForTests = callback,
                operation: () =>
                {
                    V12MasterKdf.DeriveSha3CredentialHash(
                        "AES-256",
                        "correct horse battery staple",
                        "583104",
                        factorA,
                        factorB,
                        sha3Destination);
                    return Task.CompletedTask;
                },
                failedOutputs: [sha3Destination]).ConfigureAwait(false);

            await VerifyProductionCleanupFailureAsync(
                "parallel authenticator cleanup, middle buffer",
                failAtBufferOrdinal: 2,
                expectedBufferDisposals: 4,
                configureCleanupSeam: callback => ParallelContainerAuthenticator.BeforeDerivedKeyCleanupForTests = callback,
                operation: async () =>
                {
                    using var stream = new MemoryStream(ciphertext, writable: false);
                    _ = await ParallelContainerAuthenticator.ComputeAsync(
                        stream,
                        0,
                        [prefix],
                        sha3MacKey,
                        skeinMacKey,
                        CancellationToken.None).ConfigureAwait(false);
                },
                failedOutputs: []).ConfigureAwait(false);

            await VerifyProductionCleanupFailureAsync(
                "Skein credential cleanup, last buffer",
                failAtBufferOrdinal: 4,
                expectedBufferDisposals: 4,
                configureCleanupSeam: callback => V12MasterKdf.BeforeCredentialCleanupForTests = callback,
                operation: () =>
                {
                    V12MasterKdf.DeriveSkeinCredentialHash(
                        "AES-256",
                        "correct horse battery staple",
                        "583104",
                        factorA,
                        factorB,
                        skeinDestination);
                    return Task.CompletedTask;
                },
                failedOutputs: [skeinDestination]).ConfigureAwait(false);
        }
        finally
        {
            V12MasterKdf.BeforeCredentialCleanupForTests = null;
            ParallelContainerAuthenticator.BeforeDerivedKeyCleanupForTests = null;
            SecureMemory.SensitiveBufferBeforeUnlockForTests = null;
            SecureMemory.MacMemoryUnlockOverrideForTests = null;
            SecureMemory.RetryRetainedFailedLockRollbacksForTests();
            CryptographicOperations.ZeroMemory(factorA);
            CryptographicOperations.ZeroMemory(factorB);
            CryptographicOperations.ZeroMemory(sha3Destination);
            CryptographicOperations.ZeroMemory(skeinDestination);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(prefix);
            CryptographicOperations.ZeroMemory(sha3MacKey);
            CryptographicOperations.ZeroMemory(skeinMacKey);
        }
    }

    private static async Task TestContainerWorkerMultiFailureAsync()
    {
        Exception[] expected =
        [
            new IOException("injected container worker zero failure"),
            new CryptographicException("injected container worker one failure"),
        ];
        int invoked = 0;
        Exception actual = await CaptureThrowsAsync(
            () => KalynaContainerService.RunChunkWorkersForFailureTestsAsync(
                expected.Length,
                workerIndex =>
                {
                    Interlocked.Increment(ref invoked);
                    throw expected[workerIndex];
                }),
            "Multiple injected container-worker failures were reported as success.").ConfigureAwait(false);

        Require(
            actual is AggregateException aggregate
            && aggregate.InnerExceptions.Count == expected.Length
            && aggregate.InnerExceptions
                .Select((failure, index) => ReferenceEquals(failure, expected[index]))
                .All(matches => matches),
            "Container worker failures were lost, duplicated or reordered.");
        Require(
            invoked == expected.Length,
            "The container multi-failure gate did not join every scheduled worker.");
    }

    private static async Task TestAuthenticatorWorkerMultiFailureAsync()
    {
        Exception[] expected =
        [
            new IOException("injected MAC leaf zero failure"),
            new CryptographicException("injected MAC leaf one failure"),
            new InvalidDataException("injected MAC leaf two failure"),
        ];
        Exception actual = await CaptureThrowsAsync(
            () => ParallelContainerAuthenticator.RunLeafWorkersForFailureTestsAsync(expected),
            "Multiple injected authenticator-worker failures were reported as success.").ConfigureAwait(false);

        Require(
            actual is AggregateException aggregate
            && aggregate.InnerExceptions.Count == expected.Length
            && aggregate.InnerExceptions
                .Select((failure, index) => ReferenceEquals(failure, expected[index]))
                .All(matches => matches),
            "Authenticator worker failures were lost, duplicated or reordered.");
    }

    private static async Task VerifyProductionCleanupFailureAsync(
        string label,
        int failAtBufferOrdinal,
        int expectedBufferDisposals,
        Action<Action?> configureCleanupSeam,
        Func<Task> operation,
        byte[][] failedOutputs)
    {
        long baselineBytes = SecureMemory.LockedBytesForTests;
        long baselineAllocations = SecureMemory.LockedAllocationsForTests;
        int baselineRetained = SecureMemory.RetainedFailedLockRollbacksForTests;
        int bufferDisposals = 0;
        int injectedUnlockFailures = 0;
        configureCleanupSeam(() =>
        {
            SecureMemory.SensitiveBufferBeforeUnlockForTests = () =>
            {
                if (Interlocked.Increment(ref bufferDisposals) != failAtBufferOrdinal)
                {
                    return;
                }

                int failOnce = 1;
                SecureMemory.MacMemoryUnlockOverrideForTests = (_, _) =>
                {
                    if (Interlocked.Exchange(ref failOnce, 0) == 1)
                    {
                        Interlocked.Increment(ref injectedUnlockFailures);
                        Marshal.SetLastPInvokeError(5);
                        return -1;
                    }

                    return 0;
                };
            };
        });

        try
        {
            Exception failure = await CaptureThrowsAsync(
                operation,
                $"{label}: the injected unlock failure was reported as success.").ConfigureAwait(false);
            Require(
                ContainsException<CryptographicException>(failure),
                $"{label}: the OS unlock failure was lost: {failure}");
            Require(
                bufferDisposals == expectedBufferDisposals,
                $"{label}: cleanup attempted {bufferDisposals} buffers instead of {expectedBufferDisposals}.");
            Require(injectedUnlockFailures == 1, $"{label}: the deterministic munlock seam did not fail exactly once.");
            Require(
                failedOutputs.All(output => output.AsSpan().IndexOfAnyExcept((byte)0) < 0),
                $"{label}: a failed operation left returned-key material nonzero.");
            Require(
                SecureMemory.RetainedFailedLockRollbacksForTests > baselineRetained,
                $"{label}: the failed OS lock was not retained for retry.");
            Require(
                SecureMemory.LockedAllocationsForTests > baselineAllocations,
                $"{label}: the failed OS lock disappeared from allocation accounting.");

            configureCleanupSeam(null);
            SecureMemory.SensitiveBufferBeforeUnlockForTests = null;
            SecureMemory.MacMemoryUnlockOverrideForTests = null;
            SecureMemory.RetryRetainedFailedLockRollbacksForTests();
            Require(
                SecureMemory.RetainedFailedLockRollbacksForTests == baselineRetained,
                $"{label}: retained-lock retry did not restore the retained-object baseline.");
            Require(
                SecureMemory.LockedBytesForTests == baselineBytes,
                $"{label}: retained-lock retry did not restore byte accounting.");
            Require(
                SecureMemory.LockedAllocationsForTests == baselineAllocations,
                $"{label}: retained-lock retry did not restore allocation accounting.");
        }
        finally
        {
            configureCleanupSeam(null);
            SecureMemory.SensitiveBufferBeforeUnlockForTests = null;
            SecureMemory.MacMemoryUnlockOverrideForTests = null;
            SecureMemory.RetryRetainedFailedLockRollbacksForTests();
        }
    }

    private static Task TestExtractionParentNoSideEffectsAsync()
    {
        string root = MacSafeFileSystem.ResolveExistingRealPath(
            Directory.CreateTempSubdirectory("keep-vault-extraction-parent-").FullName);
        string missingParent = Path.Combine(root, "missing", "nested");
        string realParent = Path.Combine(root, "real");
        string linkedParent = Path.Combine(root, "linked");
        Directory.CreateDirectory(realParent);
        Directory.CreateSymbolicLink(linkedParent, realParent);
        try
        {
            _ = CaptureThrows<DirectoryNotFoundException>(
                    () => new MacExtractionStaging(Path.Combine(missingParent, "archive")))
                ?? throw new InvalidOperationException("A missing extraction parent was accepted.");
            Require(!Directory.Exists(Path.Combine(root, "missing")), "A rejected missing parent created a directory tree.");

            string linkedMissingParent = Path.Combine(linkedParent, "created-through-link");
            _ = CaptureThrows<DirectoryNotFoundException>(
                    () => new MacExtractionStaging(Path.Combine(linkedMissingParent, "archive")))
                ?? throw new InvalidOperationException("A missing extraction parent below a symlink was accepted.");
            Require(
                !Directory.Exists(Path.Combine(realParent, "created-through-link")),
                "A rejected symlinked parent created a directory in the link target.");
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }

        return Task.CompletedTask;
    }

    private static Task TestRecoveryManifestJsonPreflightAsync()
    {
        byte[] validEmpty = "{\"Sections\":[]}"u8.ToArray();
        RecoveryService.ValidateManifestJsonPreflightForTests(validEmpty, archiveLength: 0);

        byte[] tooDeep = Encoding.UTF8.GetBytes(
            "{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":0}}}}}}}}}}");
        RequirePreflightRejects(tooDeep, 1, "JSON nesting deeper than the KPAR2 cap was accepted.");

        byte[] oversizedString = Encoding.UTF8.GetBytes(
            "{\"ArchiveFileName\":\"" + new string('A', 4097) + "\"}");
        RequirePreflightRejects(oversizedString, 1, "An oversized KPAR2 JSON string was accepted.");

        byte[] tooManySections = "{\"Sections\":[{},{},{}]}"u8.ToArray();
        RequirePreflightRejects(tooManySections, 1, "A third KPAR2 section was accepted by preflight.");

        byte[] dataBeyondGeometry = "{\"DataDigests\":[\"digest\"]}"u8.ToArray();
        RequirePreflightRejects(dataBeyondGeometry, 0, "A data-digest list exceeding zero-length archive geometry was accepted.");

        byte[] parityBeyondGeometry = "{\"Parity\":[{}]}"u8.ToArray();
        RequirePreflightRejects(parityBeyondGeometry, 0, "A parity list exceeding zero-length archive geometry was accepted.");

        var excessiveTokens = new StringBuilder("{");
        for (int i = 0; i < 320; i++)
        {
            if (i != 0)
            {
                excessiveTokens.Append(',');
            }

            excessiveTokens.Append("\"x\":0");
        }
        excessiveTokens.Append('}');
        RequirePreflightRejects(
            Encoding.UTF8.GetBytes(excessiveTokens.ToString()),
            0,
            "A KPAR2 manifest exceeding its token cap was accepted.");

        int geometryLimit = RecoveryService.MaximumManifestJsonBytesForTests(1);
        byte[] oversizedPayload = new byte[checked(geometryLimit + 1)];
        RequirePreflightRejects(
            oversizedPayload,
            1,
            "A KPAR2 manifest exceeding its geometry-derived byte cap was accepted.");
        return Task.CompletedTask;
    }

    private static void RequirePreflightRejects(byte[] payload, long archiveLength, string message)
    {
        try
        {
            RecoveryService.ValidateManifestJsonPreflightForTests(payload, archiveLength);
        }
        catch (Exception exception) when (exception is InvalidDataException or System.Text.Json.JsonException)
        {
            return;
        }

        throw new InvalidOperationException(message);
    }

    private static async Task TestZpaqProcessResourceLimitsAsync()
    {
        ResetZpaqResourceOverrides();
        try
        {
            Require(
                ZpaqService.DefaultMaxZpaqResidentBytes == 4L * 1024 * 1024 * 1024,
                "The production ZPAQ RSS cap is not exactly 4 GiB.");
            Require(
                ZpaqService.DefaultMaxZpaqWallTime == TimeSpan.FromHours(4),
                "The production ZPAQ wall-time cap is not exactly four hours.");
            Require(
                ZpaqService.DefaultMaxZpaqCpuTime == TimeSpan.FromHours(32),
                "The production ZPAQ aggregate CPU cap is not exactly 32 hours.");
            Require(
                ZpaqService.DefaultMaxZpaqProgressStall == TimeSpan.FromMinutes(10),
                "The production ZPAQ measurable-progress stall cap is not exactly ten minutes.");

            ZpaqService.MaxZpaqWallTimeOverride = TimeSpan.FromMilliseconds(75);
            ZpaqService.MaxZpaqCpuTimeOverride = TimeSpan.FromHours(1);
            ZpaqService.MaxZpaqResidentBytesOverride = long.MaxValue;
            ZpaqService.MaxZpaqChildProcessesOverride = 0;
            ZpaqService.ProcessMonitorIntervalOverride = TimeSpan.FromMilliseconds(10);
            var elapsed = Stopwatch.StartNew();
            Exception wallFailure = await CaptureThrowsAsync(
                () => ZpaqService.RunTextProcessAsync(
                    "/bin/sleep",
                    ["30"],
                    Path.GetTempPath(),
                    progress: null,
                    CancellationToken.None),
                "A ZPAQ process exceeded its wall-time limit without rejection.").ConfigureAwait(false);
            elapsed.Stop();
            Require(
                ContainsException<TimeoutException>(wallFailure),
                $"The wall-time gate reported the wrong failure: {wallFailure}");
            Require(elapsed.Elapsed < TimeSpan.FromSeconds(8), "The wall-time violation did not stop and join the process promptly.");

            ResetZpaqResourceOverrides();
            ZpaqService.MaxZpaqWallTimeOverride = TimeSpan.FromHours(1);
            ZpaqService.MaxZpaqCpuTimeOverride = TimeSpan.FromHours(1);
            ZpaqService.MaxZpaqResidentBytesOverride = long.MaxValue;
            ZpaqService.MaxZpaqChildProcessesOverride = 0;
            ZpaqService.MaxZpaqProgressStallOverrideForTests = TimeSpan.FromMilliseconds(75);
            ZpaqService.ProcessMonitorIntervalOverride = TimeSpan.FromMilliseconds(10);
            elapsed.Restart();
            Exception stallFailure = await CaptureThrowsAsync(
                () => ZpaqService.RunTextProcessAsync(
                    "/bin/sleep",
                    ["30"],
                    Path.GetTempPath(),
                    progress: null,
                    CancellationToken.None),
                "A ZPAQ process with no measurable progress was not rejected.").ConfigureAwait(false);
            elapsed.Stop();
            Require(
                ContainsException<TimeoutException>(stallFailure)
                    && stallFailure.ToString().Contains("no measurable", StringComparison.Ordinal),
                $"The progress-stall gate reported the wrong failure: {stallFailure}");
            Require(
                elapsed.Elapsed < TimeSpan.FromSeconds(8),
                "The progress-stall violation did not stop and join the process promptly.");

            // A hostile decoder can consume CPU forever without advancing its
            // input, output, or extraction tree. CPU time therefore must not
            // reset the independently observable progress-stall clock.
            ResetZpaqResourceOverrides();
            ZpaqService.MaxZpaqWallTimeOverride = TimeSpan.FromHours(1);
            ZpaqService.MaxZpaqCpuTimeOverride = TimeSpan.FromHours(1);
            ZpaqService.MaxZpaqResidentBytesOverride = long.MaxValue;
            ZpaqService.MaxZpaqChildProcessesOverride = 0;
            ZpaqService.MaxZpaqProgressStallOverrideForTests = TimeSpan.FromMilliseconds(75);
            ZpaqService.ProcessMonitorIntervalOverride = TimeSpan.FromMilliseconds(10);
            elapsed.Restart();
            Exception busyLoopFailure = await CaptureThrowsAsync(
                () => ZpaqService.RunTextProcessAsync(
                    "/bin/sh",
                    ["-c", "while :; do :; done"],
                    Path.GetTempPath(),
                    progress: null,
                    CancellationToken.None),
                "A CPU-burning ZPAQ process without observable forward progress was not rejected.").ConfigureAwait(false);
            elapsed.Stop();
            Require(
                ContainsException<TimeoutException>(busyLoopFailure)
                    && busyLoopFailure.ToString().Contains("no measurable", StringComparison.Ordinal),
                $"The CPU-busy progress-stall gate reported the wrong failure: {busyLoopFailure}");
            Require(
                elapsed.Elapsed < TimeSpan.FromSeconds(8),
                "The CPU-busy progress-stall violation did not stop and join the process promptly.");

            ResetZpaqResourceOverrides();
            ZpaqService.MaxZpaqResidentBytesOverride = 1;
            ZpaqService.MaxZpaqChildProcessesOverride = 1024;
            IOException rssFailure = CaptureThrows<IOException>(
                () => ZpaqService.ValidateZpaqProcessResources(Process.GetCurrentProcess(), TimeSpan.Zero))
                ?? throw new InvalidOperationException("The RSS limit accepted the current process at one byte.");
            Require(rssFailure.Message.Contains("resident-memory", StringComparison.Ordinal), "The RSS limit returned an unrelated error.");

            ResetZpaqResourceOverrides();
            ZpaqService.MaxZpaqResidentBytesOverride = long.MaxValue;
            ZpaqService.MaxZpaqCpuTimeOverride = TimeSpan.FromTicks(1);
            ZpaqService.MaxZpaqChildProcessesOverride = 1024;
            IOException cpuFailure = CaptureThrows<IOException>(
                () => ZpaqService.ValidateZpaqProcessResources(Process.GetCurrentProcess(), TimeSpan.Zero))
                ?? throw new InvalidOperationException("The CPU limit accepted an already-running process at one tick.");
            Require(cpuFailure.Message.Contains("CPU-time", StringComparison.Ordinal), "The CPU limit returned an unrelated error.");

            ResetZpaqResourceOverrides();
            ZpaqService.MaxZpaqChildProcessesOverride = 0;
            using Process process = StartProcess("/bin/sh", "-c", "sleep 30 & wait");
            try
            {
                bool childRejected = false;
                for (int attempt = 0; attempt < 100 && !childRejected; attempt++)
                {
                    await Task.Delay(10).ConfigureAwait(false);
                    try
                    {
                        ZpaqService.ValidateZpaqProcessResources(process, TimeSpan.Zero);
                    }
                    catch (IOException exception) when (exception.Message.Contains("child process", StringComparison.Ordinal))
                    {
                        childRejected = true;
                    }
                }

                Require(childRejected, "The process-count gate did not detect a persistent ZPAQ child process.");
            }
            finally
            {
                StopProcessTree(process);
            }
        }
        finally
        {
            ResetZpaqResourceOverrides();
        }
    }

    private static async Task TestZpaqFailFastErrorPreservationAsync()
    {
        var producerFailure = new InvalidDataException("producer-primary-sentinel");
        var closeFailure = new IOException("pipe-close-cleanup-sentinel");
        var failingPipe = new ThrowOnDisposeStream(closeFailure);
        var failingWriter = new StreamWriter(
            failingPipe,
            Encoding.UTF8,
            bufferSize: 1024,
            leaveOpen: false);
        Exception producerAndClose = await CaptureThrowsAsync(
            () => ZpaqService.WriteInputAndCloseAsync(
                failingWriter,
                (_, _) => Task.FromException(producerFailure),
                new ZpaqService.ProcessActivityTracker(),
                CancellationToken.None),
            "The ZPAQ input producer's close failure replaced or hid its primary failure.").ConfigureAwait(false);
        Require(
            producerAndClose is AggregateException producerAggregate
                && producerAggregate.Flatten().InnerExceptions.Any(error => ReferenceEquals(error, producerFailure))
                && producerAggregate.Flatten().InnerExceptions.Any(error => ReferenceEquals(error, closeFailure)),
            $"The input producer did not preserve primary and close failures: {producerAndClose}");

        using Process process = StartProcess("/bin/sleep", "30");
        using var linkedCts = new CancellationTokenSource();
        var cleanupFailure = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var neverCompletes = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using CancellationTokenRegistration registration = linkedCts.Token.Register(
            () => cleanupFailure.TrySetException(new IOException("cleanup-sentinel")));
        var primaryFailure = new InvalidDataException("primary-sentinel");
        ZpaqService.ProcessTaskJoinTimeoutOverrideForTests = TimeSpan.FromMilliseconds(75);
        try
        {
            Exception failure = await CaptureThrowsAsync(
                () => ZpaqService.AwaitProcessTasksFailFastAsync(
                    process,
                    linkedCts,
                    Task.FromException(primaryFailure),
                    cleanupFailure.Task,
                    neverCompletes.Task),
                "The fail-fast coordinator lost its primary child-task failure.").ConfigureAwait(false);

            Require(failure is AggregateException, "A cleanup failure was not combined with the primary failure.");
            Exception[] errors = ((AggregateException)failure).Flatten().InnerExceptions.ToArray();
            Require(errors.Any(error => ReferenceEquals(error, primaryFailure)), "The original child-task exception identity was not preserved.");
            Require(errors.Any(error => error.Message.Contains("cleanup-sentinel", StringComparison.Ordinal)), "The cleanup-task failure was not preserved.");
            Require(errors.Any(error => error is TimeoutException), "The bounded join did not preserve its timeout failure.");
            Require(process.HasExited, "The failed child task left its process running.");
        }
        finally
        {
            ZpaqService.ProcessTaskJoinTimeoutOverrideForTests = null;
            StopProcessTree(process);
        }
    }

    private static async Task TestZpaqSynchronousConsumerFailureAsync()
    {
        string root = MacSafeFileSystem.ResolveExistingRealPath(
            Directory.CreateTempSubdirectory("keep-vault-sync-consumer-failure-").FullName);
        string source = Path.Combine(root, "source.bin");
        byte[] sourceBytes = new byte[8 * 1024 * 1024];
        RandomNumberGenerator.Fill(sourceBytes);
        var sentinel = new InvalidDataException("sync-consumer-sentinel");
        try
        {
            await File.WriteAllBytesAsync(source, sourceBytes).ConfigureAwait(false);
            Exception failure = await CaptureThrowsAsync(
                () => new ZpaqService().AddStreamingAsync(
                    [source],
                    compressionLevel: 5,
                    (_, _) => throw sentinel,
                    progress: null,
                    CancellationToken.None),
                "A synchronously throwing archive consumer escaped the fail-fast coordinator.")
                .ConfigureAwait(false);

            Require(
                ReferenceEquals(failure, sentinel)
                    || failure is AggregateException aggregate
                        && aggregate.Flatten().InnerExceptions.Any(error => ReferenceEquals(error, sentinel)),
                $"The synchronous consumer exception identity was lost: {failure}");
            Require(
                FindDescendantZpaqProcessIds().Length == 0,
                "The synchronous consumer failure left a descendant zpaq process running.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sourceBytes);
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static async Task TestNativeZpaqHardeningSelfTestsAsync()
    {
        string executable = new ZpaqService().ResolveExecutable()
            ?? throw new FileNotFoundException("The staged native ZPAQ executable was not found.");
        string root = MacSafeFileSystem.ResolveExistingRealPath(
            Directory.CreateTempSubdirectory("keep-vault-zpaq-native-selftests-").FullName);
        try
        {
            await RequireNativeSelfTestAsync(
                executable,
                root,
                "--kv-self-test-root-identity-mismatch",
                expectedExitCode: 0,
                "output_root_identity_mismatch=rejected").ConfigureAwait(false);
            await RequireNativeSelfTestAsync(
                executable,
                root,
                "--kv-self-test-secure-output",
                expectedExitCode: 0,
                "output_root_descriptor_binding=verified",
                "output_case_collision=rejected",
                "output_unicode_collision=rejected",
                "output_open_failure=fail_closed",
                "output_close_ownership=preserved",
                "output_symlink_substitution=rejected").ConfigureAwait(false);
            await RequireNativeSelfTestAsync(
                executable,
                root,
                "--kv-self-test-stdio-failures",
                expectedExitCode: 0,
                "creation_fread_failure=fail_closed",
                "output_fclose_failure=fail_closed").ConfigureAwait(false);
            await RequireNativeSelfTestAsync(
                executable,
                root,
                "--kv-self-test-creation-pipeline-stdio",
                expectedExitCode: 0,
                "creation_pipeline_fread_failure=joined",
                "creation_pipeline_fclose_failure=joined").ConfigureAwait(false);
            await RequireNativeSelfTestAsync(
                executable,
                root,
                "--kv-self-test-semaphore-spurious",
                expectedExitCode: 0,
                "semaphore_spurious_wakeup=blocked").ConfigureAwait(false);
            await RequireNativeSelfTestAsync(
                executable,
                root,
                "--kv-self-test-pthread-create-failure",
                expectedExitCode: 2,
                "pthread_create failed").ConfigureAwait(false);
            await RequireNativeSelfTestAsync(
                executable,
                root,
                "--kv-self-test-pthread-join-failure",
                expectedExitCode: 2,
                "pthread_join failed").ConfigureAwait(false);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static async Task RequireNativeSelfTestAsync(
        string executable,
        string workingDirectory,
        string argument,
        int expectedExitCode,
        params string[] expectedDiagnostics)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo(executable)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WorkingDirectory = workingDirectory,
            },
        };
        process.StartInfo.ArgumentList.Add(argument);
        Require(process.Start(), $"Could not start native ZPAQ self-test {argument}.");
        Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync();
        Task<string> stderrTask = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        try
        {
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch
        {
            StopProcessTree(process);
            throw;
        }

        string diagnostics = (await stdoutTask.ConfigureAwait(false))
            + (await stderrTask.ConfigureAwait(false));
        Require(
            process.ExitCode == expectedExitCode,
            $"Native ZPAQ self-test {argument} exited {process.ExitCode}, expected {expectedExitCode}: {diagnostics}");
        foreach (string expected in expectedDiagnostics)
        {
            Require(
                diagnostics.Contains(expected, StringComparison.Ordinal),
                $"Native ZPAQ self-test {argument} omitted '{expected}': {diagnostics}");
        }
    }

    private static async Task TestPlainArchiveCommitBindingAsync()
    {
        string root = MacSafeFileSystem.ResolveExistingRealPath(
            Directory.CreateTempSubdirectory("keep-vault-three-file-commit-").FullName);
        string source = Path.Combine(root, "source.bin");
        string archive = Path.Combine(root, "archive.zpaq");
        string sha3Manifest = ArchiveIntegrityService.GetSha3ManifestPath(archive);
        string skeinManifest = ArchiveIntegrityService.GetSkeinManifestPath(archive);
        string displacedManifest = sha3Manifest + ".displaced";
        byte[] sourceBytes = RandomNumberGenerator.GetBytes(32 * 1024);
        byte[] foreignManifest = "foreign-user-manifest"u8.ToArray();
        try
        {
            await File.WriteAllBytesAsync(source, sourceBytes).ConfigureAwait(false);
            ZpaqService.PlainArchiveCommitHookAfterRenameForTests = phase =>
            {
                if (!string.Equals(phase, "archive", StringComparison.Ordinal))
                {
                    return;
                }

                File.Move(sha3Manifest, displacedManifest);
                File.WriteAllBytes(sha3Manifest, foreignManifest);
            };

            Exception failure = await CaptureThrowsAsync(
                () => new ZpaqService().AddAsync(
                    archive,
                    [source],
                    compressionLevel: 0,
                    progress: null,
                    CancellationToken.None),
                "A substituted manifest was accepted as a successful three-file commit.").ConfigureAwait(false);

            Require(
                failure is IOException or AggregateException,
                $"The substituted commit returned an unrelated error: {failure}");
            Require(
                File.Exists(sha3Manifest),
                "Rollback deleted the foreign manifest replacement. Failure: " + failure
                    + "; remaining entries: " + string.Join(", ", Directory.GetFileSystemEntries(root)));
            byte[] installedForeign = await File.ReadAllBytesAsync(sha3Manifest).ConfigureAwait(false);
            try
            {
                Require(
                    CryptographicOperations.FixedTimeEquals(installedForeign, foreignManifest),
                    "Rollback modified the foreign manifest replacement.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(installedForeign);
            }
            Require(File.Exists(displacedManifest), "Rollback deleted the displaced bound manifest under an unproven name.");
            Require(!File.Exists(archive), "Rollback left the exact committed archive installed.");
            Require(!File.Exists(skeinManifest), "Rollback left the exact committed Skein manifest installed.");
        }
        finally
        {
            ZpaqService.PlainArchiveCommitHookAfterRenameForTests = null;
            CryptographicOperations.ZeroMemory(sourceBytes);
            CryptographicOperations.ZeroMemory(foreignManifest);
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static async Task TestKeychainWrappingKeyHelperAsync()
    {
        string root = RepositoryLayout.FindRepositoryRoot();
        string scriptPath = Path.Combine(root, "tools", "Protect-HybridKeys-macOS.sh");
        string helperPath = Path.Combine(root, "KeepVaultMac", "Packaging", "AddHybridWrappingKey.c");
        string script = await File.ReadAllTextAsync(scriptPath).ConfigureAwait(false);
        string helper = await File.ReadAllTextAsync(helperPath).ConfigureAwait(false);

        Require(!script.Contains("security add-generic-password", StringComparison.Ordinal), "The wrapping key is again passed through the security CLI.");
        Require(!script.Contains("openssl rand", StringComparison.Ordinal), "The wrapping key is again generated through command substitution.");
        Require(!script.Contains(" -w ", StringComparison.Ordinal), "The wrapping key is again passed in argv.");
        Require(script.Contains("AddHybridWrappingKey.c", StringComparison.Ordinal), "The script no longer uses the in-process Keychain helper.");
        Require(script.Contains("umask 077", StringComparison.Ordinal), "The key-protection script no longer enforces private creation permissions.");
        Require(script.Contains("clang_path=$(${xcrun_path} --sdk macosx --find clang)", StringComparison.Ordinal), "The helper compiler is no longer resolved through the fixed xcrun path.");
        Require(script.Contains("require_root_system_tool ${clang_path}", StringComparison.Ordinal), "The physical helper compiler is no longer owner/mode validated.");
        Require(script.Contains("clang() { ${clang_path} \"$@\"; }", StringComparison.Ordinal), "The helper compiler wrapper no longer invokes the validated physical clang path.");
        Require(helper.Contains("SecRandomCopyBytes", StringComparison.Ordinal), "The helper no longer uses Security.framework randomness.");
        Require(helper.Contains("SecItemAdd", StringComparison.Ordinal), "The helper no longer inserts the secret directly through Security.framework.");
        Require(helper.Contains("secure_zero(encoded_key", StringComparison.Ordinal), "The helper no longer erases its encoded secret buffer.");
        Require(helper.Contains("secure_zero(random_key", StringComparison.Ordinal), "The helper no longer erases its raw secret buffer.");
    }

    private sealed record CompositeSecretFixture(Action Cleanup, byte[][] Buffers);

    private sealed class TestDisposable(Action dispose) : IDisposable
    {
        public void Dispose() => dispose();
    }

    private sealed class ThrowOnDisposeStream(Exception failure) : MemoryStream
    {
        private int _disposed;

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (disposing && Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                throw failure;
            }
        }
    }

    private static int[] FindDescendantZpaqProcessIds()
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo("/bin/ps")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            },
        };
        process.StartInfo.ArgumentList.Add("-axo");
        process.StartInfo.ArgumentList.Add("pid=,ppid=,comm=");
        if (!process.Start())
        {
            throw new InvalidOperationException("Could not inspect descendant processes after the ZPAQ failure.");
        }

        string output = process.StandardOutput.ReadToEnd();
        string error = process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"Process-tree inspection failed: {error}");
        }

        var parents = new Dictionary<int, int>();
        var commands = new Dictionary<int, string>();
        foreach (string line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            string[] fields = line.Split((char[]?)null, 3, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length == 3
                && int.TryParse(fields[0], out int processId)
                && int.TryParse(fields[1], out int parentId))
            {
                parents[processId] = parentId;
                commands[processId] = fields[2];
            }
        }

        bool IsDescendant(int processId)
        {
            var seen = new HashSet<int>();
            while (parents.TryGetValue(processId, out int parentId) && seen.Add(processId))
            {
                if (parentId == Environment.ProcessId)
                {
                    return true;
                }

                processId = parentId;
            }

            return false;
        }

        return
        [
            .. commands
                .Where(entry => string.Equals(
                    Path.GetFileName(entry.Value),
                    "zpaq",
                    StringComparison.OrdinalIgnoreCase)
                    && IsDescendant(entry.Key))
                .Select(entry => entry.Key),
        ];
    }

    private static Process StartProcess(string executable, params string[] arguments)
    {
        var startInfo = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (string argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        return Process.Start(startInfo)
            ?? throw new InvalidOperationException($"Could not start test process '{executable}'.");
    }

    private static void StopProcessTree(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(5_000);
            }
        }
        catch (InvalidOperationException)
        {
        }
    }

    private static void ResetZpaqResourceOverrides()
    {
        ZpaqService.MaxZpaqResidentBytesOverride = -1;
        ZpaqService.MaxZpaqChildProcessesOverride = -1;
        ZpaqService.MaxZpaqWallTimeOverride = null;
        ZpaqService.MaxZpaqCpuTimeOverride = null;
        ZpaqService.MaxZpaqProgressStallOverrideForTests = null;
        ZpaqService.ProcessMonitorIntervalOverride = null;
        ZpaqService.ProcessTaskJoinTimeoutOverrideForTests = null;
    }

    private static TException? CaptureThrows<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
            return null;
        }
        catch (TException expected)
        {
            return expected;
        }
    }

    private static async Task<Exception> CaptureThrowsAsync(Func<Task> action, string missingFailureMessage)
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (Exception expected)
        {
            return expected;
        }

        throw new InvalidOperationException(missingFailureMessage);
    }

    private static bool ContainsException<TException>(Exception exception)
        where TException : Exception =>
        exception is TException
            || exception is AggregateException aggregate
                && aggregate.Flatten().InnerExceptions.Any(ContainsException<TException>);

    private static void Require(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}
