using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Mono.Cecil;
using Mono.Cecil.Cil;
using PEReader = System.Reflection.PortableExecutable.PEReader;
using SectionHeader = System.Reflection.PortableExecutable.SectionHeader;

namespace JetBrainsShellPatch;

/// <summary>Outcome status for a single DLL.</summary>
internal enum PatchStatus
{
    Patched,
    AlreadyPatched,
    SkippedLocked,
    Failed
}

/// <summary>Result of attempting to patch one DLL.</summary>
internal sealed class PatchResult
{
    public required string Path { get; init; }
    public required PatchStatus Status { get; init; }
    public string? Detail { get; init; }
    public string? BackupPath { get; init; }
    public long Changes { get; init; }
}

/// <summary>Backup file used for a patch run.</summary>
internal sealed class BackupOutcome
{
    public required string Path { get; init; }
    public required string Note { get; init; }
}

/// <summary>
/// Locates the two target methods in JetBrains.Platform.Shell.dll and applies
/// metadata-free, equal-length IL byte patches. Never rewrites metadata (Cecil
/// module.Write would fail on the missing JetBrains dependency assemblies).
/// </summary>
internal sealed class DllPatcher
{
    // ECMA-335 single-byte opcodes used for the byte patches.
    private const byte OpLdarg3 = 0x05;   // ldarg.3  (reads IL arg index 3)
    private const byte OpLdcI40 = 0x16;   // ldc.i4.0
    private const byte OpNop = 0x00;      // nop
    private const byte OpRet = 0x2A;      // ret
    private const byte OpLdcI4 = 0x20;    // ldc.i4 (followed by int32)
    private const byte OpLdargS = 0x11;   // ldarg.s (followed by byte arg index)

    private const int FatMaxStack = 8;

    private const string BackupSuffix = ".backup";
    private const string CorruptBackupSuffix = ".corrupt";
    private const string TempSuffix = ".patching.tmp";

    public PatchResult Process(string dllPath, bool dryRun)
    {
        // Lock detection: try to open for exclusive write.
        if (IsLocked(dllPath))
        {
            return new PatchResult
            {
                Path = dllPath,
                Status = PatchStatus.SkippedLocked,
                Detail = "locked, close the app and retry"
            };
        }

        byte[] bytes;
        try
        {
            bytes = File.ReadAllBytes(dllPath);
        }
        catch (Exception ex)
        {
            return new PatchResult { Path = dllPath, Status = PatchStatus.Failed, Detail = "read failed: " + ex.Message };
        }

        // Locate methods + read enum OK value from metadata (no assumption it is 0).
        LocateResult locate;
        try
        {
            locate = Locate(dllPath);
        }
        catch (Exception ex)
        {
            return new PatchResult { Path = dllPath, Status = PatchStatus.Failed, Detail = "locate failed: " + ex.Message };
        }

        if (locate.Error != null)
        {
            return new PatchResult { Path = dllPath, Status = PatchStatus.Failed, Detail = locate.Error };
        }

        long changes = 0;
        var notes = new List<string>();

        // Patch A: VerifyCertificate.
        if (!locate.VerifyAlreadyPatched)
        {
            try
            {
                changes += PatchVerifyCertificate(bytes, dllPath, locate.VerifyRva, locate.EnumOkValue);
                notes.Add("VerifyCertificate -> ldc.i4(" + locate.EnumOkValue + "); ret");
            }
            catch (Exception ex)
            {
                return new PatchResult { Path = dllPath, Status = PatchStatus.Failed, Detail = "VerifyCertificate patch failed: " + ex.Message };
            }
        }

        // Patch B: AddLicense param idx3 reads.
        if (!locate.AddLicenseAlreadyPatched)
        {
            if (locate.AddLicenseUnsupported != null)
            {
                return new PatchResult { Path = dllPath, Status = PatchStatus.Failed, Detail = "AddLicense: " + locate.AddLicenseUnsupported };
            }

            try
            {
                long b = PatchAddLicense(bytes, dllPath, locate.AddLicenseRva, locate.AddLicenseIdx3Sites);
                changes += b;
                notes.Add("AddLicense: " + b + " idx3 read(s) -> ldc.i4.0");
            }
            catch (Exception ex)
            {
                return new PatchResult { Path = dllPath, Status = PatchStatus.Failed, Detail = "AddLicense patch failed: " + ex.Message };
            }
        }

        // Idempotency: both already in target state.
        if (locate.VerifyAlreadyPatched && locate.AddLicenseAlreadyPatched)
        {
            return new PatchResult { Path = dllPath, Status = PatchStatus.AlreadyPatched, Detail = "VerifyCertificate + AddLicense already patched" };
        }

        if (dryRun)
        {
            return new PatchResult
            {
                Path = dllPath,
                Status = PatchStatus.Patched,
                Detail = "[dry-run] would change " + changes + " byte(s): " + string.Join("; ", notes),
                Changes = changes
            };
        }

        // Backup (created once, never overwritten) then write.
        BackupOutcome backup;
        try
        {
            backup = EnsureBackup(dllPath);
        }
        catch (Exception ex)
        {
            return new PatchResult { Path = dllPath, Status = PatchStatus.Failed, Detail = "backup failed: " + ex.Message };
        }

        // Write through a sibling temp file so a failed write cannot leave a
        // truncated DLL behind, and restore the backup if the swap still fails.
        try
        {
            WriteAtomic(dllPath, bytes);
        }
        catch (Exception ex)
        {
            return FailedWithRestore(dllPath, "write failed: " + ex.Message, backup);
        }

        // Post-write verification (re-read the file with Cecil).
        var verify = Verifier.Verify(dllPath);
        if (!verify.Ok)
        {
            return FailedWithRestore(dllPath, "verify failed: " + verify.Message, backup);
        }

        return new PatchResult
        {
            Path = dllPath,
            Status = PatchStatus.Patched,
            Detail = string.Join("; ", notes) + "; verify PASS; " + backup.Note,
            BackupPath = backup.Path,
            Changes = changes
        };
    }

    // ---- location ----

    private sealed class LocateResult
    {
        public string? Error;
        public int VerifyRva;
        public int EnumOkValue;
        public bool VerifyAlreadyPatched;

        public int AddLicenseRva;
        public List<Idx3Site> AddLicenseIdx3Sites = new();
        public string? AddLicenseUnsupported;
        public bool AddLicenseAlreadyPatched;
    }

    /// <summary>A read of IL arg index 3 in AddLicense and the form it takes.</summary>
    private sealed class Idx3Site
    {
        public int IlOffset;
        public bool IsShortForm; // true: ldarg.3 (1 byte); false: ldarg.s 3 (2 bytes)
    }

    private static LocateResult Locate(string dllPath)
    {
        var r = new LocateResult();

        using var module = ModuleDefinition.ReadModule(dllPath);

        // (a) VerifyCertificate on UserLicenseService (any namespace).
        var service = module.GetTypes().FirstOrDefault(t => t.Name == "UserLicenseService");
        if (service == null)
        {
            r.Error = "UserLicenseService type not found";
            return r;
        }

        var verify = service.Methods.FirstOrDefault(m =>
            m.Name == "VerifyCertificate" &&
            m.IsStatic &&
            m.Parameters.Count == 4 &&
            m.Parameters[0].ParameterType.Name == "CertificateRevocationList" &&
            m.Parameters[1].ParameterType.Name == "X509Certificate2" &&
            m.Parameters[2].ParameterType.Name == "Boolean" &&
            m.Parameters[3].ParameterType.Name == "X509Certificate2[]");

        if (verify == null)
        {
            r.Error = "VerifyCertificate(CertificateRevocationList, X509Certificate2, bool, X509Certificate2[]) not found";
            return r;
        }

        r.VerifyRva = verify.RVA;
        r.EnumOkValue = ReadEnumOkValue(verify.ReturnType);

        // Idempotency: already ldc.i4*; ret ?
        var vins = verify.Body.Instructions;
        r.VerifyAlreadyPatched =
            vins.Count == 2 &&
            (vins[0].OpCode == OpCodes.Ldc_I4_0 || vins[0].OpCode == OpCodes.Ldc_I4) &&
            vins[1].OpCode == OpCodes.Ret;

        // (b) AddLicense instance method (UserLicense, bool, bool) -> bool.
        var addLicense = module.GetTypes()
            .SelectMany(t => t.Methods)
            .FirstOrDefault(m =>
                m.Name == "AddLicense" &&
                !m.IsStatic &&
                m.Parameters.Count == 3 &&
                m.Parameters[0].ParameterType.Name == "UserLicense" &&
                m.Parameters[1].ParameterType.Name == "Boolean" &&
                m.Parameters[2].ParameterType.Name == "Boolean" &&
                m.ReturnType.Name == "Boolean");

        if (addLicense == null)
        {
            r.Error = "AddLicense(UserLicense, bool, bool) -> bool not found";
            return r;
        }

        r.AddLicenseRva = addLicense.RVA;
        AnalyzeAddLicense(addLicense, r);

        return r;
    }

    /// <summary>
    /// Reads the CertificateValidationResult.OK constant straight from metadata.
    /// Does NOT assume the value is 0.
    /// </summary>
    private static int ReadEnumOkValue(TypeReference returnType)
    {
        TypeDefinition? enumDef = returnType as TypeDefinition ?? TryResolve(returnType);
        if (enumDef == null || !enumDef.IsEnum)
        {
            throw new InvalidOperationException("VerifyCertificate return type is not an enum: " + returnType.FullName);
        }

        var okField = enumDef.Fields.FirstOrDefault(f => f.Name == "OK" && f.HasConstant);
        if (okField == null)
        {
            throw new InvalidOperationException("Enum " + enumDef.FullName + " has no OK constant");
        }

        return Convert.ToInt32(okField.Constant);
    }

    private static TypeDefinition? TryResolve(TypeReference tr)
    {
        try
        {
            return tr.Resolve();
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Finds all reads of IL arg index 3 (validateLicenseKey) in AddLicense and
    /// flags unsupported write/address forms. Uses Cecil opcode identification so
    /// we never rely on a memorised byte value.
    /// </summary>
    private static void AnalyzeAddLicense(MethodDefinition m, LocateResult r)
    {
        var body = m.Body;
        var targetParam = m.Parameters[2]; // validateLicenseKey
        int targetIlIndex = 2 + (m.IsStatic ? 0 : 1); // = 3 for an instance method

        foreach (var ins in body.Instructions)
        {
            bool readsTarget =
                (ins.OpCode == OpCodes.Ldarg_3 && targetIlIndex == 3) ||
                ((ins.OpCode == OpCodes.Ldarg_S || ins.OpCode == OpCodes.Ldarg) && ReferenceEquals(ins.Operand, targetParam));

            bool addressesTarget = (ins.OpCode == OpCodes.Ldarga_S || ins.OpCode == OpCodes.Ldarga) && ReferenceEquals(ins.Operand, targetParam);
            bool writesTarget = (ins.OpCode == OpCodes.Starg_S || ins.OpCode == OpCodes.Starg) && ReferenceEquals(ins.Operand, targetParam);

            if (addressesTarget)
            {
                r.AddLicenseUnsupported = "uses ldarga on validateLicenseKey (address-of); cannot patch with equal-length replacement";
                return;
            }

            if (writesTarget)
            {
                r.AddLicenseUnsupported = "uses starg on validateLicenseKey (write); cannot patch with equal-length replacement";
                return;
            }

            if (readsTarget)
            {
                // Only the two equal-length forms are supported.
                if (ins.OpCode == OpCodes.Ldarg_3)
                {
                    r.AddLicenseIdx3Sites.Add(new Idx3Site { IlOffset = ins.Offset, IsShortForm = true });
                }
                else if (ins.OpCode == OpCodes.Ldarg_S)
                {
                    r.AddLicenseIdx3Sites.Add(new Idx3Site { IlOffset = ins.Offset, IsShortForm = false });
                }
                else
                {
                    // Long-form ldarg (rare, not used for idx 3); refuse rather than risk corruption.
                    r.AddLicenseUnsupported = "uses long-form ldarg on validateLicenseKey; unsupported";
                    return;
                }
            }
        }

        r.AddLicenseAlreadyPatched = r.AddLicenseIdx3Sites.Count == 0;
    }

    // ---- byte patching ----

    private static long PatchVerifyCertificate(byte[] bytes, string dllPath, int rva, int okValue)
    {
        int headerOffset = RvaToFileOffset(dllPath, rva);
        int codeStart = ParseFatHeaderAndCodeStart(bytes, headerOffset);

        // Rewrite fat header: FatFormat only, MaxStack=8, CodeSize per payload, LocalVarSigTok=0.
        bool isZero = okValue == 0;
        int codeSize = isZero ? 2 : 6; // ldc.i4.0;ret  vs  ldc.i4 <int32>;ret

        // flagsAndSize = (sizeDWORDs << 12) | flags. sizeDWORDs = 3 (12 bytes), flags = FatFormat(0x3).
        ushort flagsAndSize = (ushort)((3 << 12) | 0x3);
        BitConverter.GetBytes(flagsAndSize).CopyTo(bytes, headerOffset + 0);
        BitConverter.GetBytes((ushort)FatMaxStack).CopyTo(bytes, headerOffset + 2);
        BitConverter.GetBytes((uint)codeSize).CopyTo(bytes, headerOffset + 4);
        BitConverter.GetBytes((uint)0).CopyTo(bytes, headerOffset + 8); // LocalVarSigTok = 0

        if (isZero)
        {
            bytes[codeStart] = OpLdcI40;
            bytes[codeStart + 1] = OpRet;
            return 12 + 2; // header + code bytes touched (approximate change count)
        }

        bytes[codeStart] = OpLdcI4;
        BitConverter.GetBytes(okValue).CopyTo(bytes, codeStart + 1);
        bytes[codeStart + 5] = OpRet;
        return 12 + 6;
    }

    private static long PatchAddLicense(byte[] bytes, string dllPath, int rva, List<Idx3Site> sites)
    {
        int headerOffset = RvaToFileOffset(dllPath, rva);
        int codeStart = ParseFatHeaderAndCodeStart(bytes, headerOffset);

        long changes = 0;
        foreach (var site in sites)
        {
            int off = codeStart + site.IlOffset;
            if (site.IsShortForm)
            {
                // Expect ldarg.3 (0x05) -> ldc.i4.0 (0x16). Equal length (1 byte).
                Expect(bytes, off, OpLdarg3, "ldarg.3");
                bytes[off] = OpLdcI40;
                changes++;
            }
            else
            {
                // Expect ldarg.s 3 (0x11 0x03) -> ldc.i4.0; nop (0x16 0x00). Equal length (2 bytes).
                Expect(bytes, off, OpLdargS, "ldarg.s");
                Expect(bytes, off + 1, 0x03, "ldarg.s operand (arg index 3)");
                bytes[off] = OpLdcI40;
                bytes[off + 1] = OpNop;
                changes += 2;
            }
        }

        return changes;
    }

    private static void Expect(byte[] bytes, int offset, byte expected, string what)
    {
        if (bytes[offset] != expected)
        {
            throw new InvalidOperationException($"byte mismatch at 0x{offset:X8}: expected {what} = 0x{expected:X2}, found 0x{bytes[offset]:X2}");
        }
    }

    // ---- PE / method-header helpers ----

    private static int RvaToFileOffset(string dllPath, int rva)
    {
        using var fs = File.OpenRead(dllPath);
        using var pe = new PEReader(fs);
        foreach (SectionHeader s in pe.PEHeaders.SectionHeaders)
        {
            int span = Math.Max((int)s.VirtualSize, (int)s.SizeOfRawData);
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + span)
            {
                return rva - s.VirtualAddress + (int)s.PointerToRawData;
            }
        }

        throw new InvalidOperationException($"RVA 0x{rva:X8} not found in any PE section");
    }

    /// <summary>Validates the method header is Fat and returns the file offset where IL code begins.</summary>
    private static int ParseFatHeaderAndCodeStart(byte[] bytes, int headerOffset)
    {
        byte b0 = bytes[headerOffset];
        int format = b0 & 0x3;
        if (format != 0x3)
        {
            throw new InvalidOperationException($"method header format bits 0x{format:X2} (expected Fat 0x3)");
        }

        ushort flagsAndSize = BitConverter.ToUInt16(bytes, headerOffset);
        int headerSizeBytes = ((flagsAndSize >> 12) & 0xF) * 4;
        if (headerSizeBytes != 12)
        {
            throw new InvalidOperationException($"unexpected fat header size {headerSizeBytes} (expected 12)");
        }

        return headerOffset + headerSizeBytes;
    }

    private static bool IsLocked(string path)
    {
        try
        {
            using var _ = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            return false;
        }
        catch (IOException)
        {
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            // Not an app lock; treat as not locked so the real write reports the true error.
            return false;
        }
    }

    /// <summary>
    /// Ensures the single backup file next to the DLL. It is written once and
    /// never overwritten, so it keeps the original from before the first patch.
    /// A kept backup is reused only when it parses as a CLI PE image.
    /// </summary>
    private static BackupOutcome EnsureBackup(string dllPath)
    {
        string backupPath = dllPath + BackupSuffix;

        if (File.Exists(backupPath))
        {
            if (IsValidPeImage(backupPath))
            {
                return new BackupOutcome { Path = backupPath, Note = DescribeExistingBackup(backupPath, dllPath) };
            }

            string corruptPath = MoveAsideCorruptBackup(backupPath);
            CreateVerifiedBackup(dllPath, backupPath);
            return new BackupOutcome
            {
                Path = backupPath,
                Note = "corrupt backup replaced (previous copy kept as " + Path.GetFileName(corruptPath) + ")"
            };
        }

        CreateVerifiedBackup(dllPath, backupPath);
        return new BackupOutcome { Path = backupPath, Note = "backup created" };
    }

    /// <summary>
    /// Compares the kept backup with the DLL on disk. Called before the patched
    /// bytes are written, so the comparison is against the pre-patch file.
    /// </summary>
    private static string DescribeExistingBackup(string backupPath, string dllPath)
    {
        string comparison;
        try
        {
            comparison = File.ReadAllBytes(backupPath).SequenceEqual(File.ReadAllBytes(dllPath))
                ? "identical to the current file"
                : "differs from the current file, kept as-is (possibly an older build)";
        }
        catch (Exception ex)
        {
            comparison = "not comparable (" + ex.Message + ")";
        }

        return "existing backup kept, " + comparison;
    }

    /// <summary>
    /// Copies the DLL into the backup path and proves the copy is byte-identical
    /// to the pre-write file, so a short or torn copy is never kept as a restore
    /// source.
    /// </summary>
    private static void CreateVerifiedBackup(string dllPath, string backupPath)
    {
        byte[] expected = File.ReadAllBytes(dllPath);

        bool copied = false;
        try
        {
            File.Copy(dllPath, backupPath, overwrite: false);
            copied = true;

            if (!File.ReadAllBytes(backupPath).SequenceEqual(expected))
            {
                throw new IOException("backup verification failed: copy differs from " + Path.GetFileName(dllPath));
            }
        }
        catch (Exception)
        {
            if (copied)
            {
                TryDelete(backupPath);
            }

            throw;
        }
    }

    /// <summary>
    /// Structural check that a file is a CLI PE image. A truncated or overwritten
    /// backup fails this and must never be used to restore a DLL.
    /// </summary>
    private static bool IsValidPeImage(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var reader = new PEReader(stream);

            return reader.PEHeaders.PEHeader != null && reader.PEHeaders.CorHeader != null;
        }
        catch (Exception ex) when (ex is IOException or BadImageFormatException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// Moves a corrupt backup aside so its bytes stay available for inspection
    /// while a fresh backup takes its place.
    /// </summary>
    private static string MoveAsideCorruptBackup(string backupPath)
    {
        string corruptPath = backupPath + CorruptBackupSuffix;
        if (File.Exists(corruptPath))
        {
            string stamp = DateTime.UtcNow.ToString("yyyyMMddHHmmssfff");
            corruptPath = backupPath + CorruptBackupSuffix + "." + stamp;
            for (int attempt = 1; File.Exists(corruptPath); attempt++)
            {
                corruptPath = backupPath + CorruptBackupSuffix + "." + stamp + "." + attempt;
            }
        }

        File.Move(backupPath, corruptPath, overwrite: false);
        return corruptPath;
    }

    /// <summary>
    /// Writes the patched bytes to a sibling temp file and swaps it in, so the
    /// DLL is either fully old or fully new even when the write fails midway.
    /// </summary>
    private static void WriteAtomic(string dllPath, byte[] bytes)
    {
        string tempPath = dllPath + TempSuffix;
        try
        {
            File.WriteAllBytes(tempPath, bytes);
            ReplaceOrMove(tempPath, dllPath);
        }
        catch (Exception)
        {
            TryDelete(tempPath);
            throw;
        }
    }

    private static void ReplaceOrMove(string tempPath, string dllPath)
    {
        try
        {
            File.Replace(tempPath, dllPath, destinationBackupFileName: null);
        }
        catch (Exception ex) when (ex is PlatformNotSupportedException or IOException or UnauthorizedAccessException)
        {
            // File systems without atomic replace support fall back to a move.
            File.Move(tempPath, dllPath, overwrite: true);
        }
    }

    /// <summary>
    /// Reports the failure and puts the backed-up bytes back when possible, so a
    /// broken DLL is not left behind. The result still reports failure.
    /// </summary>
    private static PatchResult FailedWithRestore(string dllPath, string detail, BackupOutcome backup)
    {
        try
        {
            File.Copy(backup.Path, dllPath, overwrite: true);
        }
        catch (Exception ex)
        {
            return new PatchResult
            {
                Path = dllPath,
                Status = PatchStatus.Failed,
                Detail = detail + "; restore from backup failed: " + ex.Message,
                BackupPath = backup.Path
            };
        }

        return new PatchResult
        {
            Path = dllPath,
            Status = PatchStatus.Failed,
            Detail = detail + "; " + DescribeRestore(backup.Path, dllPath),
            BackupPath = backup.Path
        };
    }

    private static string DescribeRestore(string backupPath, string dllPath)
    {
        try
        {
            return File.ReadAllBytes(backupPath).SequenceEqual(File.ReadAllBytes(dllPath))
                ? "restored from backup"
                : "restored from backup, but the copy is not byte-identical";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return "restored from backup (comparison skipped: " + ex.Message + ")";
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Best effort: a leftover temp/corrupt file must not mask the real error.
        }
    }
}
