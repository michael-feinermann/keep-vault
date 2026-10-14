using System.IO;
internal static class RepositoryLayout
{
    public static string FindRepositoryRoot()
    {
        string? configuredRoot = Environment.GetEnvironmentVariable("KEEPVAULT_TEST_REPOSITORY_ROOT");
        if (!string.IsNullOrWhiteSpace(configuredRoot))
        {
            string root = Path.GetFullPath(configuredRoot);
            string marker = Path.Combine(root, ".git");
            if (Directory.Exists(marker) || File.Exists(marker))
            {
                return root;
            }

            throw new DirectoryNotFoundException(
                "KEEPVAULT_TEST_REPOSITORY_ROOT does not identify a checkout root.");
        }

        for (string? path = AppContext.BaseDirectory; path is not null; path = Path.GetDirectoryName(path))
        {
            string marker = Path.Combine(path, ".git");
            if (Directory.Exists(marker) || File.Exists(marker))
            {
                return path;
            }
        }

        throw new DirectoryNotFoundException("The Keep Vault repository root could not be located.");
    }

}
