using System.Collections.Generic;
using System.Reflection;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace WeProtectExe.DotNetProtector
{
    /// <summary>
    /// Adds a runtime check at the entry point that exits if a managed
    /// debugger is attached (System.Diagnostics.Debugger.IsAttached — a
    /// standard, publicly documented API, the same one legitimate
    /// licensing/DRM code has used for years). This raises the cost of
    /// dynamic analysis; it does nothing against static analysis (reading
    /// IL in dnSpy without ever running it), and a skilled analyst can
    /// patch this single check out in well under a minute once they find
    /// it. Treat it as one layer among several, not a wall — and consider
    /// making the response to detection subtler than an obvious immediate
    /// exit (e.g. a delayed or randomized response) so it's harder to
    /// correlate with the check that triggered it.
    /// </summary>
    public class AntiDebugInjector
    {
        public void Process(ModuleDefMD module)
        {
            var entry = module.EntryPoint;
            if (entry?.Body == null) return;

            var debuggerType = new TypeRefUser(module, "System.Diagnostics", "Debugger", module.CorLibTypes.AssemblyRef);
            var isAttachedGetter = new MemberRefUser(
                module, "get_IsAttached",
                MethodSig.CreateStatic(module.CorLibTypes.Boolean),
                debuggerType);

            var exitMethod = module.Import(
                typeof(System.Environment).GetMethod("Exit", new[] { typeof(int) }));

            var body = entry.Body;
            var originalFirst = body.Instructions[0];

            var check = new List<Instruction>
            {
                Instruction.Create(OpCodes.Call, isAttachedGetter),
                Instruction.Create(OpCodes.Brfalse, originalFirst),
                Instruction.CreateLdcI4(unchecked((int)0xE0000001)),
                Instruction.Create(OpCodes.Call, exitMethod),
            };

            for (int i = 0; i < check.Count; i++)
                body.Instructions.Insert(i, check[i]);
        }
    }
}
