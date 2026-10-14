/// <summary>
/// Explicit test-only compression setting for newly run complete archive and
/// Paranoia workflows. Existing recorded runs retain their original setting.
/// </summary>
internal static class ArchiveWorkflowTestSettings
{
    // Direct user preference from 4 October 2026. This is not a product default
    // or an environment override, and does not change fixed-level KAT fixtures.
    internal const int CompressionLevel = 3;
}
