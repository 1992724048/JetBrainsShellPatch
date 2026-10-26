using System;
using System.Linq;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace JetBrainsShellPatch;

/// <summary>Result of post-patch verification.</summary>
internal sealed class VerifyResult
{
    public required bool Ok { get; init; }
    public required string Message { get; init; }
}

/// <summary>
/// Re-reads a patched DLL with Cecil and asserts the two patches landed:
/// VerifyCertificate is exactly "ldc.i4(*); ret" and AddLicense has no reads
/// of IL arg index 3. Reads the file directly (never an intermediate copy).
/// </summary>
internal static class Verifier
{
    public static VerifyResult Verify(string dllPath)
    {
        try
        {
            using var module = ModuleDefinition.ReadModule(dllPath);

            // --- VerifyCertificate ---
            var service = module.GetTypes().FirstOrDefault(t => t.Name == "UserLicenseService");
            if (service == null)
            {
                return new VerifyResult { Ok = false, Message = "UserLicenseService not found on re-read" };
            }

            var verify = service.Methods.FirstOrDefault(m =>
                m.Name == "VerifyCertificate" && m.IsStatic && m.Parameters.Count == 4 &&
                m.Parameters[2].ParameterType.Name == "Boolean" &&
                m.Parameters[3].ParameterType.Name == "X509Certificate2[]");
            if (verify == null)
            {
                return new VerifyResult { Ok = false, Message = "VerifyCertificate not found on re-read" };
            }

            var vins = verify.Body.Instructions;
            bool vcOk =
                vins.Count == 2 &&
                (vins[0].OpCode == OpCodes.Ldc_I4_0 || vins[0].OpCode == OpCodes.Ldc_I4) &&
                vins[1].OpCode == OpCodes.Ret;
            if (!vcOk)
            {
                return new VerifyResult
                {
                    Ok = false,
                    Message = "VerifyCertificate IL not 'ldc.i4*; ret' (count=" + vins.Count + ", first=" + (vins.Count > 0 ? vins[0].OpCode.ToString() : "-") + ")"
                };
            }

            // --- AddLicense ---
            var addLicense = module.GetTypes()
                .SelectMany(t => t.Methods)
                .FirstOrDefault(m =>
                    m.Name == "AddLicense" && !m.IsStatic && m.Parameters.Count == 3 &&
                    m.Parameters[0].ParameterType.Name == "UserLicense" &&
                    m.Parameters[2].ParameterType.Name == "Boolean" &&
                    m.ReturnType.Name == "Boolean");
            if (addLicense == null)
            {
                return new VerifyResult { Ok = false, Message = "AddLicense not found on re-read" };
            }

            var targetParam = addLicense.Parameters[2];
            int targetIlIndex = 2 + (addLicense.IsStatic ? 0 : 1);
            int remaining = 0;
            foreach (var ins in addLicense.Body.Instructions)
            {
                bool reads =
                    (ins.OpCode == OpCodes.Ldarg_3 && targetIlIndex == 3) ||
                    ((ins.OpCode == OpCodes.Ldarg_S || ins.OpCode == OpCodes.Ldarg) && ReferenceEquals(ins.Operand, targetParam));
                if (reads)
                {
                    remaining++;
                }
            }

            if (remaining != 0)
            {
                return new VerifyResult { Ok = false, Message = "AddLicense still has " + remaining + " read(s) of validateLicenseKey" };
            }

            return new VerifyResult { Ok = true, Message = "VerifyCertificate=ldc.i4*;ret, AddLicense idx3 reads=0" };
        }
        catch (Exception ex)
        {
            return new VerifyResult { Ok = false, Message = "verify exception: " + ex.Message };
        }
    }
}
