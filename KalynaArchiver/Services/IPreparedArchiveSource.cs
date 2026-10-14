namespace KalynaArchiver.Services;

/// <summary>Starts the producer only after the container KDF has released its matrix.</summary>
internal interface IPreparedArchiveSource
{
    ValueTask PrepareForConsumptionAsync(CancellationToken cancellationToken);
}

/// <summary>Starts the consumer only after complete container authentication.</summary>
internal interface IPreparedArchiveDestination
{
    ValueTask PrepareForConsumptionAsync(CancellationToken cancellationToken);
}
