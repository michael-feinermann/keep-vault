using System.Collections;
using System.Drawing.Printing;
using System.IO;
using System.Printing;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using PdfSharp.Drawing;
using PdfSharp.Drawing.Layout;
using PdfSharp.Fonts;
using PdfSharp.Pdf;
using QRCoder;
using WpfBrushes = System.Windows.Media.Brushes;
using WpfFontFamily = System.Windows.Media.FontFamily;
using WpfHorizontalAlignment = System.Windows.HorizontalAlignment;
using WpfImage = System.Windows.Controls.Image;
using WpfOrientation = System.Windows.Controls.Orientation;
using WpfPoint = System.Windows.Point;
using WpfSize = System.Windows.Size;

namespace KalynaArchiver.Services;

public sealed partial class KeySheetService
{
    private static readonly object FontResolverGate = new();
    private static readonly string[] VirtualPrinterMarkers = ["pdf", "xps", "onenote", "fax", "send to"];

    // Explicit export uses one file per factor. Physical printing never writes a PDF.
    public void SaveTestPdf(KeySheetData data, string firstPdfPath, string secondPdfPath)
    {
        ValidatedKeySheetData validated = Validate(data);
        ArgumentException.ThrowIfNullOrWhiteSpace(firstPdfPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(secondPdfPath);
        string firstPath = Path.GetFullPath(firstPdfPath);
        string secondPath = Path.GetFullPath(secondPdfPath);
        if (string.Equals(firstPath, secondPath, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("The two factors require separate files.", nameof(secondPdfPath));
        EnsurePdfFontResolver();
        // Validate both layouts before writing either factor to persistent storage.
        using PdfDocument firstDocument = CreateSingleSheetDocument(validated, KeySheetFactor.First);
        using PdfDocument secondDocument = CreateSingleSheetDocument(validated, KeySheetFactor.Second);
        BoundFileTransaction? first = null;
        BoundFileTransaction? second = null;
        try
        {
            first = BoundFileTransaction.CreateNew(firstPath, 4096, FileOptions.WriteThrough);
            second = BoundFileTransaction.CreateNew(secondPath, 4096, FileOptions.WriteThrough);
            firstDocument.Save(first.Stream, closeStream: false);
            first.Stream.Flush(flushToDisk: true);
            secondDocument.Save(second.Stream, closeStream: false);
            second.Stream.Flush(flushToDisk: true);
        }
        catch (Exception failure)
        {
            var errors = new List<Exception> { failure };
            foreach (BoundFileTransaction? partial in new[] { second, first })
            {
                if (partial is null) continue;
                try
                {
                    partial.Stream.Position = 0;
                    byte[] zeros = new byte[4096];
                    long remaining = partial.Stream.Length;
                    while (remaining > 0)
                    {
                        int count = (int)Math.Min(zeros.Length, remaining);
                        partial.Stream.Write(zeros, 0, count);
                        remaining -= count;
                    }
                    partial.Stream.Flush(flushToDisk: true);
                    partial.DeleteBound();
                }
                catch (Exception cleanup) { errors.Add(cleanup); }
            }
            if (errors.Count > 1) throw new AggregateException("Key-sheet export and cleanup failed.", errors);
            throw;
        }
        finally { second?.Dispose(); first?.Dispose(); }
    }

    public FixedDocument CreatePrintDocument(KeySheetData data, WpfSize printableArea,
        KeySheetFactor factor = KeySheetFactor.First)
    {
        WpfSize pageSize = NormalizePageSize(printableArea);
        var document = new FixedDocument();
        document.DocumentPaginator.PageSize = pageSize;
        document.Pages.Add(CreatePage(CreatePrintVisual(data, factor), pageSize));
        document.Pages.Add(CreatePage(CreateInstallationVisual(data.English), pageSize));
        return document;
    }

    public FrameworkElement CreatePrintVisual(KeySheetData data, KeySheetFactor factor = KeySheetFactor.First)
    {
        ValidatedKeySheetData validated = Validate(data);
        return CreateSheetVisual(page => DrawPdfSheet(page, validated, factor, false));
    }

    private static FrameworkElement CreateInstallationVisual(bool english) =>
        CreateSheetVisual(page => DrawInstallationPage(page, english));

    private static FrameworkElement CreateSheetVisual(Action<SheetPage> draw)
    {
        EnsurePdfFontResolver();
        var group = new DrawingGroup();
        using (DrawingContext context = group.Open())
        {
            using var page = new SheetPage(context);
            context.DrawRectangle(WpfBrushes.White, null, new Rect(0, 0, page.Width.Point, page.Height.Point));
            draw(page);
        }
        return new WpfImage { Source = new DrawingImage(group), Stretch = Stretch.Uniform };
    }
    public static void EnsurePhysicalPrinter(PrintQueue? printQueue)
    {
        if (printQueue is null)
        {
            throw new InvalidOperationException("No printer queue is selected.");
        }

        EnsureNotVirtualPrinter($"{printQueue.Name} {printQueue.FullName} {printQueue.QueueDriver?.Name}");
    }

    public static void EnsurePhysicalPrinter(string? printerName)
    {
        if (string.IsNullOrWhiteSpace(printerName))
        {
            throw new InvalidOperationException("No printer is selected.");
        }

        EnsureNotVirtualPrinter(printerName);
    }

    private static void EnsureNotVirtualPrinter(string identifier)
    {
        if (VirtualPrinterMarkers.Any(marker => identifier.Contains(marker, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException("Virtual PDF/XPS/OneNote/Fax printers are blocked for key sheets. Use a physical printer or the explicit test-PDF export.");
        }
    }

    // Returns the first installed, valid, non-virtual printer, or null if none qualifies.
    // Used to seed the print dialog with a working printer so a broken default printer
    // driver (whose DEVMODE cannot be converted to a PrintTicket) does not make the dialog
    // unusable.
    public static string? FirstValidPhysicalPrinter()
    {
        foreach (string? name in PrinterSettings.InstalledPrinters)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                continue;
            }

            if (VirtualPrinterMarkers.Any(marker => name.Contains(marker, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            try
            {
                if (new PrinterSettings { PrinterName = name }.IsValid)
                {
                    return name;
                }
            }
            catch
            {
                // Ignore printers whose settings cannot be queried.
            }
        }

        return null;
    }

    // Prints each factor and its public guidance as a separate job through the classic GDI print
    // path (System.Drawing.Printing) instead of WPF's System.Printing pipeline. Some printer
    // drivers (e.g. the Microsoft IPP Class Driver) fail every PrintTicket<->DEVMODE
    // conversion with HRESULT 0x80004005, which breaks WPF's PrintDialog/PrintDocument even
    // for selecting a different, working printer. GDI printing does not use that provider.
    // No app-created PDF is written; secrets go only to the spooler, as with any print job.
    public void PrintKeySheets(PrinterSettings printerSettings, KeySheetData data)
    {
        ArgumentNullException.ThrowIfNull(printerSettings);
        if (printerSettings.PrintToFile)
            throw new InvalidOperationException("Print-to-file is blocked for key sheets. Use the explicit PDF export instead.");
        if (!printerSettings.IsValid)
        {
            throw new InvalidOperationException(
                $"Der ausgewählte Drucker '{printerSettings.PrinterName}' meldet eine ungültige Konfiguration (Treiber-/DEVMODE-Problem). Bitte einen anderen Drucker wählen oder den Druckertreiber neu installieren.");
        }

        EnsurePhysicalPrinter(printerSettings.PrinterName);
        if (printerSettings.Copies != 1 || printerSettings.PrintRange != PrintRange.AllPages)
            throw new InvalidOperationException("Print all pages exactly once for each separate key sheet.");
        var pageSize = new WpfSize(793.7, 1122.5);
        const double renderDpi = 200.0;
        // Render all pages before submitting either job, so a layout error cannot
        // leave the user with just one of the two factors printed.
        using var first = RenderVisualToGdiBitmap(CreatePrintVisual(data, KeySheetFactor.First), pageSize, renderDpi);
        using var second = RenderVisualToGdiBitmap(CreatePrintVisual(data, KeySheetFactor.Second), pageSize, renderDpi);
        using var guidance = RenderVisualToGdiBitmap(CreateInstallationVisual(data.English), pageSize, renderDpi);
        PrintSingleFactor(first, guidance, printerSettings, KeySheetTitle(data.English, KeySheetFactor.First));
        PrintSingleFactor(second, guidance, printerSettings, KeySheetTitle(data.English, KeySheetFactor.Second));
    }

    private static void PrintSingleFactor(System.Drawing.Bitmap factor, System.Drawing.Bitmap guidance,
        PrinterSettings settings, string title)
    {
        using var document = new PrintDocument { PrinterSettings = settings, DocumentName = title };
        document.DefaultPageSettings.Margins = new Margins(0, 0, 0, 0);
        document.DefaultPageSettings.Landscape = false;
        document.DefaultPageSettings.PaperSize = settings.PaperSizes.Cast<PaperSize>()
            .FirstOrDefault(size => size.Kind == PaperKind.A4) ?? new PaperSize("A4", 827, 1169);
        int index = 0;
        document.PrintPage += (_, args) =>
        {
            System.Drawing.Bitmap page = index == 0 ? factor : guidance;
            // GDI starts at the printable origin. Translate back to paper coordinates
            // so the common A4 layout retains its approved margins on real printers.
            args.Graphics!.TranslateTransform(-args.PageSettings.HardMarginX, -args.PageSettings.HardMarginY);
            args.Graphics.DrawImage(page, FitPreservingAspect(page.Size, args.PageBounds));
            args.HasMorePages = ++index < 2;
        };
        document.Print();
    }
    private static System.Drawing.Bitmap RenderVisualToGdiBitmap(FrameworkElement visual, WpfSize pageSize, double dpi)
    {
        visual.Width = pageSize.Width;
        visual.Height = pageSize.Height;
        visual.Measure(pageSize);
        visual.Arrange(new Rect(new WpfPoint(0, 0), pageSize));
        visual.UpdateLayout();

        int pixelWidth = (int)Math.Ceiling(pageSize.Width * dpi / 96.0);
        int pixelHeight = (int)Math.Ceiling(pageSize.Height * dpi / 96.0);
        var renderTarget = new RenderTargetBitmap(pixelWidth, pixelHeight, dpi, dpi, PixelFormats.Pbgra32);
        renderTarget.Render(visual);

        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(renderTarget));
        using var stream = new MemoryStream();
        encoder.Save(stream);
        stream.Position = 0;

        try
        {
            // Clone into a stream-independent bitmap: GDI+ requires the source stream to
            // stay open for the lifetime of a Bitmap constructed directly from it.
            using var streamBitmap = new System.Drawing.Bitmap(stream);
            return new System.Drawing.Bitmap(streamBitmap);
        }
        finally
        {
            if (stream.TryGetBuffer(out ArraySegment<byte> encodedPage))
            {
                CryptographicOperations.ZeroMemory(encodedPage.AsSpan(0, checked((int)stream.Length)));
            }
        }
    }

    private static System.Drawing.Rectangle FitPreservingAspect(System.Drawing.Size image, System.Drawing.Rectangle bounds)
    {
        if (image.Width <= 0 || image.Height <= 0 || bounds.Width <= 0 || bounds.Height <= 0)
        {
            return bounds;
        }

        double scale = Math.Min((double)bounds.Width / image.Width, (double)bounds.Height / image.Height);
        int width = Math.Max(1, (int)(image.Width * scale));
        int height = Math.Max(1, (int)(image.Height * scale));
        int x = bounds.X + ((bounds.Width - width) / 2);
        int y = bounds.Y + ((bounds.Height - height) / 2);
        return new System.Drawing.Rectangle(x, y, width, height);
    }

    public static byte[] CreateQrPng(string generatedPassword)
    {
        string normalized = PasswordKeyService.NormalizeGeneratedPassword(generatedPassword);
        using var generator = new QRCodeGenerator();
        using QRCodeData data = generator.CreateQrCode(normalized, QRCodeGenerator.ECCLevel.Q);
        using var png = new PngByteQRCode(data);
        try { return png.GetGraphic(6); }
        finally { foreach (BitArray row in data.ModuleMatrix) row.SetAll(false); }
    }

    /// <summary>
    /// The factor in four eight-character groups per line.
    /// </summary>
    /// <remarks>
    /// The same shape the macOS sheet uses. Breaking the lines here rather than
    /// letting the formatter wrap them is what makes the block's height
    /// predictable, which is what FactorBlockHeight needs to guarantee that
    /// none of it is dropped.
    /// </remarks>
    public static string GroupGeneratedPasswordForSheet(string generatedPassword)
    {
        string normalized = PasswordKeyService.NormalizeGeneratedPassword(generatedPassword);
        var groups = Enumerable.Range(0, normalized.Length / 8)
            .Select(index => normalized.Substring(index * 8, 8))
            .ToList();
        var lines = new List<string>();
        // Five groups to a row rather than four. A 256-character factor is 32
        // groups, so five per row is seven rows instead of eight, and the row
        // that saves is what pays for the larger type: this block is read by
        // eye and typed by hand, which is the whole reason it is printed.
        const int groupsPerRow = 5;
        for (int i = 0; i < groups.Count; i += groupsPerRow)
        {
            int count = Math.Min(groupsPerRow, groups.Count - i);
            lines.Add(string.Join(' ', groups.GetRange(i, count)));
        }

        return string.Join(Environment.NewLine, lines);
    }

    /// <summary>
    /// How tall the factor block has to be for every one of its lines to be drawn.
    /// </summary>
    /// <remarks>
    /// XTextFormatter drops whole lines that do not fit the rectangle it is
    /// given, and it does so silently. The macOS sheet lost the last 32 of its
    /// 256 hexadecimal characters that way, to a height constant that was one
    /// line short. This one was a hand-picked 112 with a comment calling it
    /// generous; generous is not a property a sheet that has to open an archive
    /// should rely on. Measured from the font instead.
    /// </remarks>
    internal static double FactorBlockHeight(XFont monoFont, string groupedFactor)
    {
        ArgumentNullException.ThrowIfNull(monoFont);
        ArgumentNullException.ThrowIfNull(groupedFactor);
        int lines = groupedFactor.Split('\n').Length;
        return (lines * monoFont.GetHeight()) + 4;
    }

    public static string GroupGeneratedPassword(string generatedPassword)
    {
        string normalized = PasswordKeyService.NormalizeGeneratedPassword(generatedPassword);
        return string.Join(" ", Enumerable.Range(0, normalized.Length / 8).Select(i => normalized.Substring(i * 8, 8)));
    }

    private static string GetGeneratedPassword(KeySheetData data, KeySheetFactor factor)
    {
        return PasswordKeyService.NormalizeGeneratedPassword(
            factor == KeySheetFactor.First ? data.FirstGeneratedPassword : data.SecondGeneratedPassword);
    }

    private static WpfSize NormalizePageSize(WpfSize printableArea)
    {
        return printableArea.Width > 100 && printableArea.Height > 100
            ? printableArea
            : new WpfSize(793.7, 1122.5); // A4 at WPF's 96 DPI unit.
    }

    private static PageContent CreatePage(FrameworkElement visual, WpfSize pageSize)
    {
        visual.Width = pageSize.Width;
        visual.Height = pageSize.Height;
        visual.Measure(pageSize);
        visual.Arrange(new Rect(new WpfPoint(0, 0), pageSize));
        visual.UpdateLayout();

        var fixedPage = new FixedPage { Width = pageSize.Width, Height = pageSize.Height, Background = WpfBrushes.White };
        fixedPage.Children.Add(visual);
        return new PageContent { Child = fixedPage };
    }

    private static PageContent CreateBlankPage(WpfSize pageSize)
    {
        var fixedPage = new FixedPage { Width = pageSize.Width, Height = pageSize.Height, Background = WpfBrushes.White };
        return new PageContent { Child = fixedPage };
    }

    private static TextBlock Label(string text)
    {
        return new TextBlock
        {
            Text = text,
            FontSize = 13,
            FontWeight = FontWeights.SemiBold,
            Foreground = WpfBrushes.Black,
            Margin = new Thickness(0, 0, 0, 4),
        };
    }

    private static TextBlock Value(string text)
    {
        return new TextBlock
        {
            Text = text,
            FontSize = 12,
            TextWrapping = TextWrapping.Wrap,
            Foreground = WpfBrushes.Black,
            Margin = new Thickness(0, 0, 0, 16),
        };
    }

    private static Border FieldLine()
    {
        return new Border
        {
            BorderBrush = WpfBrushes.Black,
            BorderThickness = new Thickness(0, 0, 0, 1),
            Height = 28,
            Margin = new Thickness(0, 0, 0, 8),
        };
    }

    private static BitmapImage CreateBitmap(byte[] pngBytes)
    {
        using var stream = new MemoryStream(pngBytes);
        var image = new BitmapImage();
        image.BeginInit();
        image.CacheOption = BitmapCacheOption.OnLoad;
        image.StreamSource = stream;
        image.EndInit();
        image.Freeze();
        return image;
    }

    /// <remarks>
    /// Internal rather than private so the suite can measure the factor block
    /// without drawing a sheet first, as the macOS side already does.
    /// </remarks>
    internal static void EnsurePdfFontResolver()
    {
        lock (FontResolverGate)
        {
            if (GlobalFontSettings.FontResolver is null)
            {
                GlobalFontSettings.FontResolver = WindowsFontResolver.Instance;
            }
        }
    }
}

public enum KeySheetFactor
{
    First,
    Second,
}

public sealed record KeySheetData(
    string ArchivePath,
    EncryptionSuite Suite,
    string FirstGeneratedPassword,
    string SecondGeneratedPassword,
    DateTime CreatedAt,
    bool English = false,
    string DeviceName = "");

internal sealed class WindowsFontResolver : IFontResolver
{
    private const int MaximumFontBytes = 64 * 1024 * 1024;
    public static readonly WindowsFontResolver Instance = new();
    private static readonly IReadOnlyDictionary<string, string> FontFiles = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["segoeui"] = "segoeui.ttf",
        ["segoeuib"] = "segoeuib.ttf",
        ["segoeuii"] = "segoeuii.ttf",
        ["segoeuiz"] = "segoeuiz.ttf",
        ["consola"] = "consola.ttf",
        ["consolab"] = "consolab.ttf",
        ["arial"] = "arial.ttf",
        ["arialbd"] = "arialbd.ttf",
        ["cour"] = "cour.ttf",
        ["courbd"] = "courbd.ttf",
    };

    private WindowsFontResolver()
    {
    }

    public FontResolverInfo? ResolveTypeface(string familyName, bool bold, bool italic)
    {
        string family = familyName.Trim();
        if (family.Contains("courier", StringComparison.OrdinalIgnoreCase))
            return new FontResolverInfo(bold ? "courbd" : "cour", false, italic);
        if (family.Contains("consol", StringComparison.OrdinalIgnoreCase))
        {
            return new FontResolverInfo(bold ? "consolab" : "consola", false, italic);
        }

        if (family.Contains("segoe", StringComparison.OrdinalIgnoreCase))
        {
            string face = (bold, italic) switch
            {
                (true, true) => "segoeuiz",
                (true, false) => "segoeuib",
                (false, true) => "segoeuii",
                _ => "segoeui",
            };
            return new FontResolverInfo(face);
        }

        return new FontResolverInfo(bold ? "arialbd" : "arial", false, italic);
    }

    public byte[] GetFont(string faceName)
    {
        if (!FontFiles.TryGetValue(faceName, out string? fileName))
        {
            fileName = "arial.ttf";
        }

        string fontPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Fonts", fileName);
        if (!File.Exists(fontPath))
        {
            throw new FileNotFoundException($"PDF font not found: {fontPath}", fontPath);
        }

        using var stream = new FileStream(
            fontPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 64 * 1024,
            FileOptions.SequentialScan);
        if (stream.Length is <= 0 or > MaximumFontBytes)
        {
            throw new InvalidDataException($"PDF font has an invalid bounded length: {fontPath}");
        }

        byte[] font = new byte[checked((int)stream.Length)];
        stream.ReadExactly(font);
        return font;
    }
}
