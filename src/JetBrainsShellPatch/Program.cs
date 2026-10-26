using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace JetBrainsShellPatch;

internal static class Program
{
    private const int ExitAllOk = 0;
    private const int ExitFailure = 1;
    private const int ExitNoDll = 2;

    private static int Main(string[] args)
    {
        int exitCode = Run(args);

        // Double-click experience: keep the window open to show results when the
        // tool is launched with no arguments from an interactive console.
        if (args.Length == 0 && !Console.IsInputRedirected)
        {
            Console.WriteLine();
            Console.WriteLine("Press any key to exit...");
            try
            {
                Console.ReadKey(intercept: true);
            }
            catch (InvalidOperationException)
            {
                // No console input attached; nothing to wait for.
            }
        }

        return exitCode;
    }

    private static int Run(string[] args)
    {
        string? path = null;
        bool dryRun = false;

        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            if (a == "--dry-run")
            {
                dryRun = true;
            }
            else if (a == "--path")
            {
                if (i + 1 >= args.Length)
                {
                    Console.Error.WriteLine("ERROR: --path requires a directory argument.");
                    return ExitFailure;
                }

                path = args[++i];
            }
            else if (a == "--help" || a == "-h" || a == "/?")
            {
                PrintUsage();
                return ExitAllOk;
            }
            else
            {
                Console.Error.WriteLine("ERROR: unknown argument: " + a);
                PrintUsage();
                return ExitFailure;
            }
        }

        string targetDir = path ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "JetBrains",
            "Installations");

        if (!Directory.Exists(targetDir))
        {
            Console.WriteLine("No DLL found: target directory does not exist -> " + targetDir);
            return ExitNoDll;
        }

        List<string> dlls;
        try
        {
            dlls = Directory
                .EnumerateFiles(targetDir, "JetBrains.Platform.Shell.dll", SearchOption.AllDirectories)
                .OrderBy(p => p, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("ERROR: failed to enumerate '" + targetDir + "': " + ex.Message);
            return ExitFailure;
        }

        if (dlls.Count == 0)
        {
            Console.WriteLine("No JetBrains.Platform.Shell.dll found under: " + targetDir);
            return ExitNoDll;
        }

        var patcher = new DllPatcher();
        var results = new List<PatchResult>();

        Console.WriteLine("Target directory: " + targetDir);
        Console.WriteLine("Mode: " + (dryRun ? "dry-run (no files will be written)" : "patch"));
        Console.WriteLine("DLLs found: " + dlls.Count);
        Console.WriteLine();

        foreach (string dll in dlls)
        {
            PatchResult r = patcher.Process(dll, dryRun);
            results.Add(r);
            Console.WriteLine(FormatResult(r));
        }

        Console.WriteLine();
        PrintSummary(results);

        bool hasFailure = results.Any(r => r.Status == PatchStatus.Failed);
        return hasFailure ? ExitFailure : ExitAllOk;
    }

    private static string FormatResult(PatchResult r)
    {
        string status = r.Status switch
        {
            PatchStatus.Patched => "PATCHED",
            PatchStatus.AlreadyPatched => "ALREADY PATCHED",
            PatchStatus.SkippedLocked => "SKIPPED",
            PatchStatus.Failed => "FAILED",
            _ => "UNKNOWN"
        };

        var line = $"[{status}] {r.Path}";
        if (!string.IsNullOrEmpty(r.Detail))
        {
            line += "  (" + r.Detail + ")";
        }

        if (!string.IsNullOrEmpty(r.BackupPath))
        {
            line += Environment.NewLine + "         backup: " + r.BackupPath;
        }

        return line;
    }

    private static void PrintSummary(List<PatchResult> results)
    {
        int patched = results.Count(r => r.Status == PatchStatus.Patched);
        int already = results.Count(r => r.Status == PatchStatus.AlreadyPatched);
        int skipped = results.Count(r => r.Status == PatchStatus.SkippedLocked);
        int failed = results.Count(r => r.Status == PatchStatus.Failed);

        Console.WriteLine("==== Summary ====");
        Console.WriteLine("  PATCHED        : " + patched);
        Console.WriteLine("  ALREADY PATCHED: " + already);
        Console.WriteLine("  SKIPPED (locked): " + skipped);
        Console.WriteLine("  FAILED         : " + failed);
        Console.WriteLine("  TOTAL          : " + results.Count);
    }

    private static void PrintUsage()
    {
        Console.WriteLine("JetBrainsShellPatch - patch JetBrains.Platform.Shell.dll license checks (dev/debug use).");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  JetBrainsShellPatch.exe [--path <directory>] [--dry-run]");
        Console.WriteLine();
        Console.WriteLine("Options:");
        Console.WriteLine("  --path <directory>  Search this directory (recursively) for JetBrains.Platform.Shell.dll.");
        Console.WriteLine("                      Default: %LOCALAPPDATA%\\JetBrains\\Installations");
        Console.WriteLine("  --dry-run           Only detect and report; do not write any file.");
        Console.WriteLine("  --help, -h, /?      Show this help.");
        Console.WriteLine();
        Console.WriteLine("Exit codes: 0 = all ok / nothing to do, 1 = at least one FAILED, 2 = no DLL found.");
        Console.WriteLine();
        Console.WriteLine("Close the target JetBrains application first so the DLL is not file-locked.");
    }
}
