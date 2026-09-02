namespace KalynaArchiver.Services;

/// <summary>
/// Optional random-access implementation used by platform-specific private
/// snapshot streams whose underlying descriptor cannot be read directly.
/// </summary>
internal interface IPrivateSnapshotRandomAccess
{
    ValueTask<int> ReadAtAsync(
        Memory<byte> destination,
        long offset,
        CancellationToken cancellationToken);
}
