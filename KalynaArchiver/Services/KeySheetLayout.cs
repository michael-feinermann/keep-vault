using Color = System.Windows.Media.Color;
using Point = System.Windows.Point;
using FontFamily = System.Windows.Media.FontFamily;
using FlowDirection = System.Windows.FlowDirection;
using Pen = System.Windows.Media.Pen;
using System.Collections;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text;
using System.Windows;
using System.Windows.Media;
using PdfSharp.Drawing;
using PdfSharp.Pdf;
using QRCoder;

namespace KalynaArchiver.Services;

public sealed partial class KeySheetService
{
    private const string ProductName = "Keep Vault";
    private const string ProjectUrl = "https://github.com/michael-feinermann/keep-vault";
    private const double MinimumFontSize = 16;
    private const double FactorFontSize = 14;
    private static string VersionedProductName => ProductName + " " +
        (typeof(KeySheetService).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
         ?? typeof(KeySheetService).Assembly.GetName().Version!.ToString(3));
    private static string KeySheetTitle(bool english, KeySheetFactor factor) => english
        ? $"{VersionedProductName} Key Sheet {(factor == KeySheetFactor.First ? "A" : "B")}"
        : $"{VersionedProductName} Schlüsselzettel {(factor == KeySheetFactor.First ? "A" : "B")}";

    private static ValidatedKeySheetData Validate(KeySheetData data)
    {
        ArgumentNullException.ThrowIfNull(data);
        string first = PasswordKeyService.NormalizeGeneratedPassword(data.FirstGeneratedPassword);
        string second = PasswordKeyService.NormalizeGeneratedPassword(data.SecondGeneratedPassword);
        if (string.Equals(first, second, StringComparison.Ordinal))
            throw new ArgumentException("Die Faktoren A und B müssen verschieden sein.", nameof(data));
        return new ValidatedKeySheetData(Path.GetFullPath(data.ArchivePath), data.Suite,
            EncryptionSuiteCatalog.DisplayName(data.Suite, data.English), first, second,
            data.CreatedAt, data.English,
            string.IsNullOrWhiteSpace(data.DeviceName) ? Environment.MachineName + " (Windows)" : data.DeviceName.Trim());
    }

    private static PdfDocument CreateSingleSheetDocument(ValidatedKeySheetData data, KeySheetFactor factor)
    {
        var document = new PdfDocument();
        try
        {
            document.Info.Title = KeySheetTitle(data.English, factor);
            document.Info.Author = ProductName;
            using (var page = new SheetPage(document.AddPage())) DrawPdfSheet(page, data, factor, false);
            using (var page = new SheetPage(document.AddPage())) DrawInstallationPage(page, data.English);
            return document;
        }
        catch { document.Dispose(); throw; }
    }

    // PDF and physical printing execute the same layout and use the same font metrics.
    // The WPF backend only translates drawing operations; it never writes a PDF.
    private sealed class SheetPage : IDisposable
    {
        internal XUnit Width { get; set; } = XUnit.FromMillimeter(210);
        internal XUnit Height { get; set; } = XUnit.FromMillimeter(297);
        internal SheetGraphics Graphics { get; }
        internal SheetPage(PdfPage page)
        {
            page.Width = Width; page.Height = Height;
            Graphics = new SheetGraphics(XGraphics.FromPdfPage(page), null);
        }
        internal SheetPage(DrawingContext context) => Graphics = new SheetGraphics(
            XGraphics.CreateMeasureContext(new XSize(Width.Point, Height.Point), XGraphicsUnit.Point, XPageDirection.Downwards), context);
        public void Dispose() => Graphics.Dispose();
    }

    private sealed class SheetGraphics(XGraphics metrics, DrawingContext? drawing) : IDisposable
    {
        internal XSize MeasureString(string value, XFont font) => metrics.MeasureString(value, font);
        private static SolidColorBrush Brush(XBrush value)
        {
            XColor color = ((XSolidBrush)value).Color;
            return new SolidColorBrush(Color.FromArgb((byte)Math.Round(color.A * 255), color.R, color.G, color.B));
        }
        internal void DrawString(string value, XFont font, XBrush brush, XPoint point)
        {
            if (drawing is null) { metrics.DrawString(value, font, brush, point); return; }
            var face = new Typeface(new FontFamily(font.Name2), font.Italic ? FontStyles.Italic : FontStyles.Normal,
                font.Bold ? FontWeights.Bold : FontWeights.Normal, FontStretches.Normal);
            var text = new FormattedText(value, CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
                face, font.Size, Brush(brush), 1);
            drawing.DrawText(text, new Point(point.X, point.Y - text.Baseline));
        }
        internal void DrawRectangle(XBrush brush, double x, double y, double width, double height)
        {
            if (drawing is null) metrics.DrawRectangle(brush, x, y, width, height);
            else drawing.DrawRectangle(Brush(brush), null, new Rect(x, y, width, height));
        }
        internal void DrawLine(XPen pen, double x1, double y1, double x2, double y2)
        {
            if (drawing is null) metrics.DrawLine(pen, x1, y1, x2, y2);
            else drawing.DrawLine(new Pen(new SolidColorBrush(Color.FromRgb(pen.Color.R, pen.Color.G, pen.Color.B)), pen.Width), new Point(x1,y1), new Point(x2,y2));
        }
        internal void DrawBlock(string value, XFont font, XBrush brush, XRect bounds)
        {
            double y = bounds.Y + font.GetHeight() * 0.8;
            foreach (string line in value.Split('\n'))
            {
                DrawString(line.TrimEnd('\r'), font, brush, new XPoint(bounds.X, y));
                y += font.GetHeight();
            }
        }
        public void Dispose() => metrics.Dispose();
    }

    private sealed record ValidatedKeySheetData(string CanonicalArchivePath, EncryptionSuite Suite,
        string SuiteDisplayName, string FirstGeneratedPassword, string SecondGeneratedPassword,
        DateTime CreatedAt, bool English, string DeviceName);
    private static void DrawPdfSheet(
        SheetPage page,
        ValidatedKeySheetData data,
        KeySheetFactor factor,
        bool separatedByBlankPage)
    {
        SetA4(page);
        string generatedPassword = factor == KeySheetFactor.First
            ? data.FirstGeneratedPassword
            : data.SecondGeneratedPassword;
        string factorName = factor == KeySheetFactor.First ? "A" : "B";
        bool en = data.English;

        SheetGraphics graphics = page.Graphics;
        var titleFont = new XFont("Arial", 22, XFontStyleEx.Bold);
        var headingFont = new XFont("Arial", 14, XFontStyleEx.Bold);
        var normalFont = new XFont("Arial", 12);
        var warningFont = new XFont("Arial", 13, XFontStyleEx.Bold);
        var shoutFont = new XFont("Arial", 16, XFontStyleEx.Bold);
        var passwordFont = new XFont("Arial", 16, XFontStyleEx.Bold);
        var pinWarningFont = new XFont("Arial", 14, XFontStyleEx.Bold);
        var factorFont = new XFont("Courier New", FactorFontSize, XFontStyleEx.Bold);


        const double margin = 36;
        double bodyWidth = page.Width.Point - (2 * margin);
        double y = 40;

        DrawWrappedValue(graphics, titleFont, KeySheetTitle(en, factor),
            margin, bodyWidth, ref y, lineHeight: titleFont.GetHeight() + 2);
        y += 5;
        DrawWrappedValue(
            graphics,
            warningFont,
            separatedByBlankPage
                ? (en
                    ? "Keep this key sheet separate from the other one. The page between A and B separates the two factors on purpose."
                    : "Diesen Schlüsselzettel getrennt vom anderen aufbewahren. Die Seite zwischen A und B trennt beide Faktoren absichtlich.")
                : (en
                    ? "Keep this key sheet separate from the other one. Each sheet contains only one factor."
                    : "Diesen Schlüsselzettel getrennt vom anderen aufbewahren. Jeder Zettel enthält nur einen Faktor."),
            margin, bodyWidth, ref y, XBrushes.DarkRed, warningFont.GetHeight() + 2);
        y += 3;
        graphics.DrawString(
            en ? "DO NOT THROW AWAY!" : "NICHT WEGSCHMEISSEN!",
            shoutFont, XBrushes.Red, new XPoint(margin, y));
        y += 25;

        // Fixed reservations keep all three handwriting rows, the complete
        // 14-point factor and both full-size QR symbols independent of metadata.
        const double qrSize = 132;
        const double qrGap = 28;
        double footerBaseline = page.Height.Point - 28;
        double urlBaseline = footerBaseline - 24;
        double urlLabelBaseline = urlBaseline - 17;
        double qrTop = urlLabelBaseline - 20 - qrSize;
        double qrHeadingBaseline = qrTop - 11;
        string groupedFactor = GroupGeneratedPasswordForSheet(generatedPassword);
        double factorBlockHeight = FactorBlockHeight(factorFont, groupedFactor);
        double factorBlockTop = qrHeadingBaseline - headingFont.GetHeight() - 12 - factorBlockHeight;
        double factorHeadingBaseline = factorBlockTop - 22;

        const int writingLines = 3;
        double writingSpacing = XUnit.FromMillimeter(9).Point;
        double writingBottom = factorHeadingBaseline - 24;
        double writingTop = writingBottom - (writingLines * writingSpacing);
        double writingHeadingBaseline = writingTop - 34;

        (string Label, string Value)[] metadata =
        [
            (en ? "Encryption suite:" : "Verschlüsselungssuite:", data.SuiteDisplayName),
            (en ? "Archive file:" : "Archivdatei:", Path.GetFileName(data.CanonicalArchivePath)),
            (en ? "Created on device:" : "Erstellt auf Gerät:", data.DeviceName),
            (en ? "Storage location:" : "Speicherort:",
                Path.GetDirectoryName(data.CanonicalArchivePath) ?? data.CanonicalArchivePath),
        ];
        XFont? metadataFont = null;
        XFont? metadataLabelFont = null;
        List<(string Label, List<string> ValueLines)>? metadataLines = null;
        double metadataLineHeight = 0;
        foreach (double fontSize in new[] { 13.0, 12.0 })
        {
            var candidateFont = new XFont("Arial", fontSize);
            var candidateLabelFont = new XFont("Arial", fontSize, XFontStyleEx.Bold);
            var candidateLines = metadata
                .Select(item => (item.Label, ValueLines: WrapToWidth(
                    graphics, candidateFont, item.Value, bodyWidth,
                    bodyWidth - graphics.MeasureString(item.Label, candidateLabelFont).Width
                        - graphics.MeasureString(" ", candidateFont).Width)))
                .ToList();
            double candidateLineHeight = Math.Max(candidateFont.GetHeight(), candidateLabelFont.GetHeight()) + 2;
            double requiredHeight = candidateLines.Sum(item => item.ValueLines.Count * candidateLineHeight + 5);
            if (y + requiredHeight <= writingHeadingBaseline - 18)
            {
                metadataFont = candidateFont;
                metadataLabelFont = candidateLabelFont;
                metadataLines = candidateLines;
                metadataLineHeight = candidateLineHeight;
                break;
            }
        }

        if (metadataFont is null || metadataLabelFont is null || metadataLines is null)
        {
            // Reject an unprintable layout instead of omitting metadata,
            // removing handwriting rows or obscuring any factor/QR content.
            throw new InvalidOperationException(en
                ? "The archive name, storage location or device name is too long for a fully readable key sheet with three password lines. Use shorter names or a shorter storage location."
                : "Archivname, Speicherort oder Gerätename ist zu lang für einen vollständig lesbaren Schlüsselzettel mit drei Passwortzeilen. Verwende kürzere Namen oder einen kürzeren Speicherort.");
        }

        foreach ((string label, List<string> valueLines) in metadataLines)
        {
            for (int lineIndex = 0; lineIndex < valueLines.Count; lineIndex++)
            {
                double valueX = margin;
                if (lineIndex == 0)
                {
                    graphics.DrawString(label, metadataLabelFont, XBrushes.Black, new XPoint(margin, y));
                    valueX += graphics.MeasureString(label, metadataLabelFont).Width
                        + graphics.MeasureString(" ", metadataFont).Width;
                }
                graphics.DrawString(valueLines[lineIndex], metadataFont, XBrushes.Black, new XPoint(valueX, y));
                y += metadataLineHeight;
            }
            y += 5;
        }

        graphics.DrawString(en ? "User password" : "Benutzerpasswort",
            passwordFont, XBrushes.Black, new XPoint(margin, writingHeadingBaseline));
        string pinWarning = en ? "Do not write down the PIN" : "PIN nicht eintragen";
        double pinWarningWidth = graphics.MeasureString(pinWarning, pinWarningFont).Width;
        graphics.DrawString(pinWarning, pinWarningFont, XBrushes.DarkRed,
            new XPoint(page.Width.Point - margin - pinWarningWidth, writingHeadingBaseline));
        graphics.DrawString(en ? "Write by hand, never store digitally." : "Von Hand eintragen, nicht digital speichern.",
            normalFont, XBrushes.Black, new XPoint(margin, writingHeadingBaseline + 18));
        for (int index = 1; index <= writingLines; index++)
        {
            double lineY = writingTop + (writingSpacing * index);
            graphics.DrawLine(XPens.Black, margin, lineY, page.Width.Point - margin, lineY);
        }

        graphics.DrawString(
            en
                ? $"Generated hexadecimal 1024-bit factor {factorName}"
                : $"Generierter hexadezimaler 1024-Bit-Faktor {factorName}",
            headingFont, XBrushes.Black, new XPoint(margin, factorHeadingBaseline));
        graphics.DrawBlock(groupedFactor, factorFont, XBrushes.Black,
            new XRect(margin, factorBlockTop, bodyWidth, factorBlockHeight));

        graphics.DrawString(
            en
                ? $"Both QR codes: factor {factorName} only (error correction Q)"
                : $"Beide QR-Codes: ausschließlich Faktor {factorName} (Fehlerkorrektur Q)",
            warningFont, XBrushes.Black, new XPoint(margin, qrHeadingBaseline));

        // Two identical symbols preserve the existing redundant scan path.
        // Their payload still contains only this sheet's normalized factor.
        string qrPayload = PasswordKeyService.NormalizeGeneratedPassword(generatedPassword);
        double qrLeft = margin + ((bodyWidth - (2 * qrSize) - qrGap) / 2);
        DrawQrCode(graphics, qrPayload, qrLeft, qrTop, qrSize);
        DrawQrCode(graphics, qrPayload, qrLeft + qrSize + qrGap, qrTop, qrSize);

        graphics.DrawString(
            en ? "Download and verify the app at:" : "App herunterladen und prüfen unter:",
            normalFont, XBrushes.Black, new XPoint(margin, urlLabelBaseline));
        graphics.DrawString(ProjectUrl, normalFont, XBrushes.DarkBlue, new XPoint(margin, urlBaseline));
        string footer = en
            ? $"Created: {data.CreatedAt:yyyy-MM-dd HH:mm:ss}    Keep offline and physically protected."
            : $"Erstellt: {data.CreatedAt:yyyy-MM-dd HH:mm:ss}    Offline und physisch geschützt aufbewahren.";
        graphics.DrawString(footer, normalFont, XBrushes.DarkSlateGray, new XPoint(margin, footerBaseline));
    }

    /// <summary>
    /// Draws the public installation guidance page for each separate key sheet.
    /// </summary>
    /// <remarks>
    /// Nothing here depends on the archive or on either factor: this method
    /// deliberately takes no key-sheet data at all, so the guidance page
    /// cannot leak anything even if it is later edited carelessly.
    /// </remarks>
    private static void DrawInstallationPage(SheetPage page, bool en)
    {
        SetA4(page);
        SheetGraphics graphics = page.Graphics;
        var titleFont = new XFont("Arial", 24, XFontStyleEx.Bold);
        var headingFont = new XFont("Arial", MinimumFontSize, XFontStyleEx.Bold);
        var normalFont = new XFont("Arial", MinimumFontSize);

        const double margin = 42;
        const double bodyWidth = 500;
        double y = margin;

        graphics.DrawString(
            en ? "Installing Keep Vault" : "Keep Vault installieren",
            titleFont,
            XBrushes.Black,
            new XPoint(margin, y));
        y += 34;

        DrawWrappedValue(
            graphics,
            normalFont,
            en
                ? "This page contains only public installation guidance and no key material."
                : "Diese Seite enthält nur öffentliche Installationshinweise und kein Schlüsselmaterial.",
            margin,
            bodyWidth,
            ref y);
        y += 14;

        graphics.DrawString(
            en ? "Download" : "Bezugsquelle",
            headingFont,
            XBrushes.Black,
            new XPoint(margin, y));
        y += 22;
        graphics.DrawString(ProjectUrl, normalFont, XBrushes.DarkBlue, new XPoint(margin, y));
        y += 14;

        DrawQrCode(graphics, ProjectUrl, margin, y, 126);
        y += 126 + 30;

        graphics.DrawString("Windows", headingFont, XBrushes.Black, new XPoint(margin, y));
        y += 24;
        DrawSteps(graphics, normalFont, margin, bodyWidth, ref y, en
            ? [
                "1. Download the Windows release from the page above.",
                "2. Extract the complete ZIP into a new folder.",
                "3. Run Keep Vault Setup.exe to verify and install the package. No .NET SDK is required.",
                "4. The installer verifies the dual signature before it creates any shortcut.",
            ]
            : [
                "1. Windows-Release von der oben genannten Seite herunterladen.",
                "2. Die vollständige ZIP-Datei in einen neuen Ordner entpacken.",
                "3. Keep Vault Setup.exe prüft und installiert das Paket. Ein .NET SDK ist nicht erforderlich.",
                "4. Der Installer prüft die duale Signatur, bevor er eine Verknüpfung anlegt.",
            ]);
        y += 16;

        graphics.DrawString("macOS", headingFont, XBrushes.Black, new XPoint(margin, y));
        y += 24;
        DrawSteps(graphics, normalFont, margin, bodyWidth, ref y, en
            ? [
                "1. Download the macOS release from the page above.",
                "2. Extract the ZIP file. The .khsig files belong next to Keep Vault.app and must stay there.",
                "3. Follow that release's instructions to verify the signatures and install the app.",
                "4. QR-Scanner.app in the same package reads the factor QR codes on the key sheets. Keep Vault never uses the camera.",
                "5. The app checks Apple's signature and its own dual signature at every start.",
            ]
            : [
                "1. macOS-Release von der oben genannten Seite herunterladen.",
                "2. Die ZIP-Datei entpacken. Die .khsig-Dateien gehören neben Keep Vault.app und müssen dort bleiben.",
                "3. Installation und Signaturprüfung nach der Anleitung des jeweiligen Releases durchführen.",
                "4. QR-Scanner.app aus demselben Paket liest die Faktor-QR-Codes auf den Schlüsselzetteln. Keep Vault nutzt die Kamera nie.",
                "5. Die App prüft bei jedem Start Apples Signatur und ihre eigene duale Signatur.",
            ]);

        string footer = en
            ? "Keep this page with the key sheets."
            : "Diese Seite bei den Schlüsselzetteln aufbewahren.";
        graphics.DrawString(footer, normalFont, XBrushes.DarkSlateGray, new XPoint(margin, page.Height.Point - 24));
    }

    /// <summary>
    /// Draws numbered steps, wrapping each one to the page width.
    /// </summary>
    /// <remarks>
    /// Drawn line by line rather than into a fixed rectangle: a clipped
    /// rectangle silently drops the end of the last instruction, which on a
    /// sheet nobody re-reads before filing is a mistake that only surfaces when
    /// the instructions are actually needed.
    /// </remarks>
    private static void DrawSteps(
        SheetGraphics graphics,
        XFont font,
        double x,
        double width,
        ref double y,
        string[] steps)
    {
        foreach (string step in steps)
        {
            DrawWrappedValue(graphics, font, step, x, width, ref y);
            y += 4;
        }
    }

    private static void DrawLabelAndValue(
        SheetGraphics graphics,
        XFont headingFont,
        XFont normalFont,
        string label,
        string value,
        double x,
        double width,
        ref double y)
    {
        graphics.DrawString(label, headingFont, XBrushes.Black, new XPoint(x, y));
        y += 22;
        DrawWrappedValue(graphics, normalFont, value, x, width, ref y);
        y += 12;
    }

    /// <summary>
    /// Draws a value across as many lines as it needs, breaking inside long
    /// unbroken strings.
    /// </summary>
    /// <remarks>
    /// A storage location is a single token with no spaces, and at this font
    /// size it is easily wider than the page. Word wrapping alone would run it
    /// off the right edge, which is how a sheet ends up telling its owner only
    /// half of where the archive is, so the break falls after a path separator
    /// where possible and mid-token where not.
    /// </remarks>
    private static void DrawWrappedValue(
        SheetGraphics graphics,
        XFont font,
        string value,
        double x,
        double width,
        ref double y,
        XBrush? brush = null,
        double lineHeight = 20)
    {
        XBrush ink = brush ?? XBrushes.Black;
        foreach (string line in WrapToWidth(graphics, font, value, width))
        {
            graphics.DrawString(line, font, ink, new XPoint(x, y));
            y += lineHeight;
        }
    }

    private static List<string> WrapToWidth(
        SheetGraphics graphics, XFont font, string value, double width, double? firstLineWidth = null)
    {
        var lines = new List<string>();
        if (string.IsNullOrEmpty(value))
        {
            lines.Add(string.Empty);
            return lines;
        }

        var current = new StringBuilder();
        int lastBreak = -1;
        double availableWidth = firstLineWidth ?? width;
        foreach (char character in value)
        {
            current.Append(character);
            if (character is '/' or ' ' or '\\' or '-' or '_')
            {
                lastBreak = current.Length;
            }

            if (graphics.MeasureString(current.ToString(), font).Width <= availableWidth)
            {
                continue;
            }

            // Prefer the last separator, but never emit an empty line: if the
            // overflow happens before any separator, break mid-token instead.
            int cut = lastBreak > 0 && lastBreak < current.Length ? lastBreak : current.Length - 1;
            if (cut <= 0)
            {
                cut = 1;
            }

            lines.Add(current.ToString(0, cut).TrimEnd());
            availableWidth = width;
            string remainder = current.ToString(cut, current.Length - cut).TrimStart();
            current.Clear();
            current.Append(remainder);
            lastBreak = -1;
        }

        if (current.Length > 0)
        {
            lines.Add(current.ToString());
        }

        return lines;
    }

    /// <summary>
    /// Draws one QR code for an arbitrary payload.
    /// </summary>
    /// <remarks>
    /// Factor payloads are normalised by their caller, so what is encoded here
    /// is exactly what the scanner will be checked against. The matrix is
    /// cleared afterwards because for a factor it is key material.
    /// </remarks>
    private static void DrawQrCode(SheetGraphics graphics, string payload, double x, double y, double size)
    {
        using var generator = new QRCodeGenerator();
        using QRCodeData qrData = generator.CreateQrCode(payload, QRCodeGenerator.ECCLevel.Q);
        try
        {
            int moduleCount = qrData.ModuleMatrix.Count;
            double moduleSize = size / moduleCount;
            graphics.DrawRectangle(XBrushes.White, x, y, size, size);

            for (int row = 0; row < moduleCount; row++)
            {
                BitArray rowData = qrData.ModuleMatrix[row];
                for (int column = 0; column < moduleCount; column++)
                {
                    if (rowData[column])
                    {
                        graphics.DrawRectangle(
                            XBrushes.Black,
                            x + (column * moduleSize),
                            y + (row * moduleSize),
                            moduleSize + 0.05,
                            moduleSize + 0.05);
                    }
                }
            }
        }
        finally
        {
            ClearQrMatrix(qrData);
        }
    }

    private static void ClearQrMatrix(QRCodeData qrData)
    {
        foreach (BitArray row in qrData.ModuleMatrix)
        {
            row.SetAll(false);
        }
    }

    private static void SetA4(SheetPage page)
    {
        page.Width = XUnit.FromMillimeter(210);
        page.Height = XUnit.FromMillimeter(297);
    }

}
