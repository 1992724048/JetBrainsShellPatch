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
/// of its validateLicenseKey parameter. Reads the file directly (never an intermediate copy).
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
                .FirstOrDefault(IsSupportedAddLicenseMethod);
            if (addLicense == null)
            {
                return new VerifyResult { Ok = false, Message = "AddLicense(Lifetime, UserLicense, bool validateLicenseKey, bool) -> Task<bool> not found on re-read" };
            }

            var targetParam = GetValidateLicenseKeyParameter(addLicense);
            int targetIlIndex = addLicense.Parameters.IndexOf(targetParam) + (addLicense.IsStatic ? 0 : 1);
            int remaining = 0;
            foreach (var instruction in addLicense.Body.Instructions)
            {
                bool reads =
                    IsShortLdargRead(instruction.OpCode, targetIlIndex) ||
                    ((instruction.OpCode == OpCodes.Ldarg_S || instruction.OpCode == OpCodes.Ldarg) && ReferenceEquals(instruction.Operand, targetParam));
                if (reads)
                {
                    remaining++;
                }
            }

            if (remaining != 0)
            {
                return new VerifyResult { Ok = false, Message = "AddLicense still has " + remaining + " read(s) of validateLicenseKey" };
            }

            return new VerifyResult { Ok = true, Message = "VerifyCertificate=ldc.i4*;ret, AddLicense validateLicenseKey reads=0" };
        }
        catch (Exception ex)
        {
            return new VerifyResult { Ok = false, Message = "verify exception: " + ex.Message };
        }
    }

    private static bool IsSupportedAddLicenseMethod(MethodDefinition method)
    {
        if (method.Name != "AddLicense" || method.IsStatic)
        {
            return false;
        }

        if (method.Parameters.Count != 4)
        {
            return false;
        }

        if (!HasUserLicenseParameter(method))
        {
            return false;
        }

        if (!HasBooleanTailParameters(method))
        {
            return false;
        }

        return IsSupportedAddLicenseReturnType(method.ReturnType);
    }

    private static bool HasUserLicenseParameter(MethodDefinition method)
    {
        foreach (var parameter in method.Parameters)
        {
            if (parameter.ParameterType.Name == "UserLicense")
            {
                return true;
            }
        }

        return false;
    }

    private static bool HasBooleanTailParameters(MethodDefinition method)
    {
        int count = method.Parameters.Count;
        return method.Parameters[count - 1].ParameterType.Name == "Boolean" &&
               method.Parameters[count - 2].ParameterType.Name == "Boolean";
    }

    private static bool IsSupportedAddLicenseReturnType(TypeReference returnType)
    {
        if (returnType is GenericInstanceType generic && generic.Name == "Task`1")
        {
            if (generic.GenericArguments.Count == 1 && generic.GenericArguments[0].Name == "Boolean")
            {
                return true;
            }
        }

        return false;
    }

    private static ParameterDefinition GetValidateLicenseKeyParameter(MethodDefinition method)
    {
        foreach (var parameter in method.Parameters)
        {
            if (parameter.Name == "validateLicenseKey" && parameter.ParameterType.Name == "Boolean")
            {
                return parameter;
            }
        }

        for (int index = method.Parameters.Count - 1; index >= 0; index--)
        {
            if (method.Parameters[index].ParameterType.Name == "Boolean")
            {
                return method.Parameters[index];
            }
        }

        return method.Parameters[method.Parameters.Count - 1];
    }

    private static bool IsShortLdargRead(OpCode opCode, int targetIlIndex)
    {
        return (opCode == OpCodes.Ldarg_0 && targetIlIndex == 0) ||
               (opCode == OpCodes.Ldarg_1 && targetIlIndex == 1) ||
               (opCode == OpCodes.Ldarg_2 && targetIlIndex == 2) ||
               (opCode == OpCodes.Ldarg_3 && targetIlIndex == 3);
    }
}
