using System.Windows.Media;
using System.Windows.Media.Imaging;

internal static class RenderEvidenceGuard
{
    // These are blank-image checks, not a visual design or readability test.
    // Every captured surface has an opaque background and substantial content.
    internal static void RequireUsable(BitmapSource bitmap, string name)
    {
        if (bitmap.Format != PixelFormats.Pbgra32 && bitmap.Format != PixelFormats.Bgra32)
            throw new InvalidOperationException("Render evidence must use a reviewed 32-bit BGRA pixel format.");

        int count = checked(bitmap.PixelWidth * bitmap.PixelHeight);
        if (count == 0) throw new InvalidOperationException("Render evidence has no pixels.");
        var pixels = new int[count];
        bitmap.CopyPixels(pixels, checked(bitmap.PixelWidth * sizeof(int)), 0);

        // Quantized RGB buckets keep the histogram bounded even for noisy images.
        var histogram = new int[4096];
        var representatives = new int[4096];
        int visible = 0, dominant = 0;
        foreach (int pixel in pixels)
        {
            if ((uint)pixel >> 24 < 128) continue;
            visible++;
            int bucket = ((pixel >> 12) & 0xF00) | ((pixel >> 8) & 0xF0) | ((pixel >> 4) & 0xF);
            if (histogram[bucket]++ == 0) representatives[bucket] = pixel;
            if (histogram[bucket] > histogram[dominant]) dominant = bucket;
        }

        int background = representatives[dominant];
        int contrast = 0;
        foreach (int pixel in pixels)
        {
            if ((uint)pixel >> 24 < 128) continue;
            if (Math.Abs((pixel & 255) - (background & 255)) >= 16
                || Math.Abs(((pixel >> 8) & 255) - ((background >> 8) & 255)) >= 16
                || Math.Abs(((pixel >> 16) & 255) - ((background >> 16) & 255)) >= 16)
                contrast++;
        }

        int requiredVisible = Math.Max(64, count / 10);
        int requiredContrast = Math.Max(64, count / 1000);
        if (visible < requiredVisible || contrast < requiredContrast)
            throw new InvalidOperationException(
                $"GUI render '{name}' is not usable visual evidence: {visible}/{count} visible pixels "
                + $"(required {requiredVisible}), {contrast} pixels contrasting with the dominant colour "
                + $"(required {requiredContrast}). Re-run with an active interactive Windows desktop session "
                + "and check the WPF rendering environment. Transparent, empty or flat renders must not pass visual acceptance.");
    }

    // No renderer or native window is involved in these guard regressions.
    internal static void RunSyntheticTests()
    {
        const int width = 100, height = 100;
        int[] Solid(uint colour) => Enumerable.Repeat(unchecked((int)colour), width * height).ToArray();
        BitmapSource Image(int[] pixels) => BitmapSource.Create(width, height, 96, 96,
            PixelFormats.Bgra32, null, pixels, width * sizeof(int));
        void Reject(int[] pixels, string name)
        {
            try { RequireUsable(Image(pixels), name); }
            catch (InvalidOperationException error) when (error.Message.Contains("not usable visual evidence", StringComparison.Ordinal)) { return; }
            throw new InvalidOperationException($"The render guard accepted invalid synthetic evidence: {name}.");
        }

        Reject(Solid(0), "transparent");
        Reject(Solid(0xFF000000), "solid black");
        Reject(Solid(0xFFFFFFFF), "solid white");
        Reject(Solid(0xFF08101D), "solid theme background");
        int[] invisibleColour = Solid(0x00000000);
        Array.Fill(invisibleColour, 0x00FFFFFF, 0, invisibleColour.Length / 2);
        Reject(invisibleColour, "colour variation without visible alpha");
        int[] sparse = Solid(0);
        Array.Fill(sparse, unchecked((int)0xFF000000), 0, 100);
        Array.Fill(sparse, unchecked((int)0xFFFFFFFF), 100, 100);
        Reject(sparse, "too few visible pixels");
        int[] isolated = Solid(0xFFFFFFFF);
        isolated[0] = unchecked((int)0xFF000000);
        Reject(isolated, "one contrasting pixel");
        int[] almostFlat = Solid(0xFF202020);
        Array.Fill(almostFlat, unchecked((int)0xFF212121), 0, almostFlat.Length / 2);
        Reject(almostFlat, "insignificant colour variation");

        foreach (uint background in new uint[] { 0xFF08101D, 0xFFFFFFFF })
        {
            int[] content = Solid(background);
            Array.Fill(content, unchecked((int)(background == 0xFFFFFFFF ? 0xFF000000u : 0xFFFFFFFFu)), 0, 1000);
            RequireUsable(Image(content), "synthetic visible content");
        }
    }
}
