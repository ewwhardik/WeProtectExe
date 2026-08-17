using System;
using System.Collections.Generic;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace WeProtectExe.DotNetProtector
{
    /// <summary>
    /// Replaces every string literal (ldstr) with an encrypted byte blob and
    /// a call into a merged-in runtime decryptor. This defeats naive
    /// "strings.exe" / static string scanning; it does NOT defeat someone
    /// willing to set a breakpoint on the decrypt call and dump the return
    /// value — no string encryption scheme does, since the key has to live
    /// somewhere reachable at runtime to be usable at all. Treat this as
    /// raising the bar against automated scanners, not analysts.
    ///
    /// PREREQUISITE: WeProtectExe.Runtime.dll (built from Runtime/StrDec.cs)
    /// must already be merged into the target module before this pass runs
    /// — e.g. with ILRepack as a build step:
    ///     ilrepack /out:merged.exe target.exe WeProtectExe.Runtime.dll
    /// Run StringEncryptor against `merged.exe`, not the original target.
    /// </summary>
    public class StringEncryptor
    {
        private readonly byte[] _key;
        private MethodDef _decryptMethod;
        private ITypeDefOrRef _byteArrayElemType;

        public StringEncryptor(byte[] key) => _key = key;

        public void Process(ModuleDefMD module)
        {
            ResolveDecryptor(module);
            InjectKeyInit(module);

            foreach (var type in module.GetTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (method.Body == null) continue;
                    var instrs = method.Body.Instructions;

                    for (int i = 0; i < instrs.Count; i++)
                    {
                        if (instrs[i].OpCode != OpCodes.Ldstr) continue;
                        var plain = instrs[i].Operand as string;
                        if (string.IsNullOrEmpty(plain)) continue;

                        var cipher = Xor(Encoding.UTF8.GetBytes(plain), _key);
                        var replacement = BuildArrayAndCallSequence(cipher, _decryptMethod);

                        instrs.RemoveAt(i);
                        for (int k = 0; k < replacement.Count; k++)
                            instrs.Insert(i + k, replacement[k]);
                        i += replacement.Count - 1;
                    }
                }
            }
        }

        private void ResolveDecryptor(ModuleDefMD module)
        {
            var runtimeType = module.Find("WeProtectExe.Runtime.StrDec", true);
            if (runtimeType == null)
                throw new InvalidOperationException(
                    "WeProtectExe.Runtime.dll must be merged into the target module before " +
                    "running StringEncryptor. See the header comment on this file.");

            _decryptMethod = runtimeType.FindMethod("D");
            if (_decryptMethod == null)
                throw new InvalidOperationException("Could not find StrDec.D in the merged runtime type.");

            _byteArrayElemType = module.CorLibTypes.Byte.ToTypeDefOrRef();
        }

        private void InjectKeyInit(ModuleDefMD module)
        {
            var keyType = module.Find("WeProtectExe.Runtime.Key", true);
            var initMethod = keyType?.FindMethod("Init");
            if (initMethod == null)
                throw new InvalidOperationException("Could not find Key.Init in the merged runtime type.");

            var entry = module.EntryPoint;
            if (entry?.Body == null)
                throw new InvalidOperationException("Module has no entry point to inject the key setup into.");

            var setup = BuildArrayAndCallSequence(_key, initMethod);
            for (int i = 0; i < setup.Count; i++)
                entry.Body.Instructions.Insert(i, setup[i]);
        }

        /// <summary>
        /// Emits: build a byte[] literal on the stack from `data`, then call
        /// `target(byte[])`. Used both for encrypted string payloads and for
        /// handing the key to Key.Init at startup.
        /// </summary>
        private List<Instruction> BuildArrayAndCallSequence(byte[] data, IMethod target)
        {
            var instrs = new List<Instruction>
            {
                Instruction.CreateLdcI4(data.Length),
                Instruction.Create(OpCodes.Newarr, _byteArrayElemType)
            };

            for (int b = 0; b < data.Length; b++)
            {
                instrs.Add(Instruction.Create(OpCodes.Dup));
                instrs.Add(Instruction.CreateLdcI4(b));
                instrs.Add(Instruction.CreateLdcI4(data[b]));
                instrs.Add(Instruction.Create(OpCodes.Stelem_I1));
            }

            instrs.Add(Instruction.Create(OpCodes.Call, target));
            return instrs;
        }

        private static byte[] Xor(byte[] data, byte[] key)
        {
            var outp = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
                outp[i] = (byte)(data[i] ^ key[i % key.Length]);
            return outp;
        }
    }
}
