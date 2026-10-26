# JetBrainsShellPatch

Dev/debug helper that patches `JetBrains.Platform.Shell.dll` to bypass two license
checks. It locates the target methods by name + signature (no hard-coded offsets),
keeps a single `<dll>.backup` copy of the original, and verifies the result by
re-reading the file.

> For development and debugging only. See "Risks & Disclaimer" below.

## What it patches

Both changes are **metadata-free, equal-length IL byte patches**. Cecil is used only
to *locate* methods and *read* enum constants from metadata; the file is never
rewritten via `module.Write` (that would fail on the missing JetBrains dependency
assemblies). Assembly identity (public key / token) is preserved byte-for-byte.

1. **`VerifyCertificate`** — on `UserLicenseService` (any namespace), the static
   `VerifyCertificate(CertificateRevocationList, X509Certificate2, bool, X509Certificate2[])`.
   The whole method body is replaced with `ldc.i4(OK); ret`, so it always returns
   `CertificateValidationResult.OK`. The `OK` constant value is read from metadata
   (not assumed to be `0`). The method's fat header is rewritten (FatFormat,
   MaxStack=8, CodeSize=2, LocalVarSigTok=0, MoreSects/InitLocals cleared).

2. **`AddLicense`** — the instance `AddLicense(UserLicense, bool doCheckSynchronousely, bool validateLicenseKey)`.
   Every read of the `validateLicenseKey` parameter (IL arg index 3) is replaced so
   it behaves as `false`:
   - `ldarg.3` (`0x05`) → `ldc.i4.0` (`0x16`) — equal length, 1 byte
   - `ldarg.s 3` (`0x11 0x03`) → `ldc.i4.0; nop` (`0x16 0x00`) — equal length, 2 bytes

   If the parameter is ever address-of'd (`ldarga`) or written (`starg`), the DLL is
   reported `FAILED` rather than risk corruption.

## Build

Requires the .NET SDK 10.0 or later.

```powershell
dotnet build JetBrainsShellPatch.sln -c Release
```

## Publish (single-file exe)

```powershell
dotnet publish src\JetBrainsShellPatch -c Release -r win-x64 `
  --self-contained true -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true -o publish
```

The result is a single self-contained `JetBrainsShellPatch.exe`.

## Usage

Double-click `JetBrainsShellPatch.exe`, or run from a terminal:

```powershell
# Patch every DLL under %LOCALAPPDATA%\JetBrains\Installations (default target)
JetBrainsShellPatch.exe

# Only report what would change; write nothing
JetBrainsShellPatch.exe --dry-run

# Patch a specific directory tree
JetBrainsShellPatch.exe --path "D:\Some\JetBrains\Installations"
```

**Close the target JetBrains application before running**, otherwise the DLL is
file-locked and the entry is reported `SKIPPED (locked)`.

### Options

| Option | Meaning |
| ------ | ------- |
| `--path <dir>` | Search `<dir>` recursively for `JetBrains.Platform.Shell.dll` (overrides the default target). |
| `--dry-run` | Detect and report only; do not write any file. |
| `--help`, `-h`, `/?` | Show usage. |

### Per-DLL status

| Status | Meaning |
| ------ | ------- |
| `PATCHED` | The DLL was backed up, patched, and verified. |
| `ALREADY PATCHED` | Both patches were already in place; nothing written. |
| `SKIPPED` | The DLL is locked (app running); close the app and retry. |
| `FAILED` | Something went wrong; the detail explains why. |

### Exit codes

| Code | Meaning |
| ---- | ------- |
| `0` | All DLLs succeeded or needed no action. |
| `1` | At least one DLL reported `FAILED`. |
| `2` | No `JetBrains.Platform.Shell.dll` was found. |

## Backup & rollback

Exactly one backup is kept per DLL: `<dll>.backup`, next to the DLL.

- Created only on the first patch run and **never overwritten** afterwards, so it
  always keeps the original from before the first patch.
- A run that reports `ALREADY PATCHED` writes nothing and creates no backup.
- If `<dll>.backup` already exists it is reused as-is; the reported detail states
  whether it is identical to or different from the current DLL.

Rollback is a single file copy:

```powershell
Copy-Item "JetBrains.Platform.Shell.dll.backup" "JetBrains.Platform.Shell.dll" -Force
```

## Risks & Disclaimer

- **Strong-name signature is invalidated.** Editing IL breaks the strong-name
  signature, so `sn -vf` verification fails. .NET Core / .NET 5+ do not verify
  strong names at runtime, so this is expected and harmless for dev/debug.
- **Product updates overwrite the patch.** Any JetBrains update/upgrade that
  replaces `JetBrains.Platform.Shell.dll` restores the original checks; re-run the
  tool after updating.
- **File lock.** Close the target JetBrains application first, or the DLL cannot be
  opened for writing and will be reported `SKIPPED`.
- **Use at your own risk.** This tool is intended for development and debugging of
  software you are licensed to use. Bypassing license checks may violate the
  software's terms of service or licensing agreement. The authors accept no liability.

## Limitations

- Only `JetBrains.Platform.Shell.dll` is ever patched; no other file is touched.
- No system or global environment is modified; NuGet packages are project-local.
- Requires the target DLL's `AddLicense` to read `validateLicenseKey` only via
  `ldarg.3` / `ldarg.s 3`. `ldarga`/`starg` usage fails fast instead of patching.
- The single backup is never refreshed: after a JetBrains update replaces the DLL,
  the old `<dll>.backup` is kept and reported as differing from the current file.
  Delete it manually if you want the next run to capture the new original.
