using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using KalynaArchiver.Services;
using PdfSharp.Pdf.IO;

internal static class KeySheetV502Tests
{
    internal static void Run()
    {
        string? evidence = Environment.GetEnvironmentVariable("KEEPVAULT_KEY_SHEET_EVIDENCE");
        string root = evidence is null ? Directory.CreateTempSubdirectory("keep-vault-sheet-v502-").FullName : Path.GetFullPath(evidence);
        Directory.CreateDirectory(root);
        try
        {
            var service = new KeySheetService();
            string first = string.Concat(Enumerable.Repeat("0123456789ABCDEF", 16));
            string second = string.Concat(Enumerable.Repeat("FEDCBA9876543210", 16));
            foreach (bool english in new[] { false, true })
            {
                string language = english ? "en" : "de";
                var data = new KeySheetData(@"C:\Archive\Familienarchiv.kzpaq", EncryptionSuite.ParanoiaCascade,
                    first, second, new DateTime(2026, 9, 9, 12, 0, 0), english, "Windows Test Device");
                bool printToFileBlocked = false;
                try { service.PrintKeySheets(new System.Drawing.Printing.PrinterSettings { PrintToFile = true }, data); }
                catch (InvalidOperationException exception) { printToFileBlocked = exception.Message.StartsWith("Print-to-file", StringComparison.Ordinal); }
                Require(printToFileBlocked, "Print-to-file is refused by the service before querying a printer or submitting a job.");
                string a = Path.Combine(root, language + "-A.pdf");
                string b = Path.Combine(root, language + "-B.pdf");
                service.SaveTestPdf(data, a, b);
                foreach ((string path, string factor) in new[] { (a, "A"), (b, "B") })
                {
                    using var document = PdfReader.Open(path, PdfDocumentOpenMode.Import);
                    Require(document.PageCount == 2, "Each factor has exactly one sheet plus public guidance.");
                    Require(document.Info.Title == $"Keep Vault 5.0.2 {(english ? "Key Sheet" : "Schlüsselzettel")} {factor}",
                        "Localized document title includes the actual release version.");
                }
                byte[] before = SHA256.HashData(File.ReadAllBytes(a));
                ExpectFailure(() => service.SaveTestPdf(data, a, b));
                Require(before.SequenceEqual(SHA256.HashData(File.ReadAllBytes(a))), "Existing exports are never overwritten.");
                string partial = Path.Combine(root, language + "-partial.pdf");
                ExpectFailure(() => service.SaveTestPdf(data, partial, b));
                Require(!File.Exists(partial), "A second-file conflict cleans up the first bound file.");
                string same = Path.Combine(root, language + "-same.pdf");
                ExpectFailure(() => service.SaveTestPdf(data, same, same.ToUpperInvariant()));
                Require(!File.Exists(same), "Windows case aliases cannot merge the two factors.");

                foreach (KeySheetFactor factor in Enum.GetValues<KeySheetFactor>())
                {
                    var print = service.CreatePrintDocument(data, new Size(793.7, 1122.5), factor);
                    Require(print.Pages.Count == 2, "Every print job contains only one factor and public guidance.");
                    if (evidence is not null)
                    {
                        for (int page = 0; page < print.Pages.Count; page++)
                        {
                            var visual = print.Pages[page].Child;
                            visual.Measure(new Size(793.7, 1122.5));
                            visual.Arrange(new Rect(0, 0, 793.7, 1122.5));
                            visual.UpdateLayout();
                            var bitmap = new RenderTargetBitmap(1191, 1684, 144, 144, PixelFormats.Pbgra32);
                            bitmap.Render(visual);
                            RenderEvidenceGuard.RequireUsable(bitmap, $"{language}-{factor}-print-{page + 1}");
                            var encoder = new PngBitmapEncoder();
                            encoder.Frames.Add(BitmapFrame.Create(bitmap));
                            using var file = new FileStream(Path.Combine(root, $"{language}-{factor}-print-{page + 1}.png"), FileMode.CreateNew);
                            encoder.Save(file);
                        }
                    }
                }
            }
        }
        finally { if (evidence is null) Directory.Delete(root, recursive: true); }
    }

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private static void ExpectFailure(Action action)
    {
        try { action(); }
        catch (Exception exception) when (exception is IOException or ArgumentException) { return; }
        throw new InvalidOperationException("The unsafe key-sheet export was not rejected.");
    }
}
