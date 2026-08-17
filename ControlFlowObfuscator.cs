using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace WeProtectExe.DotNetProtector
{
    /// <summary>
    /// Inserts opaque predicates and dead junk blocks into method bodies.
    /// The branch condition is always true by construction (for any integer
    /// x, (x*x) % 4 is always 0 or 1, never 2), so program behavior is
    /// unchanged — but a decompiler has to actually prove that to fold the
    /// branch away, and most don't bother, so the reader gets shown a fake
    /// fork in the logic plus a block of code that never runs.
    ///
    /// This is a mitigation against casual static reading, not a wall —
    /// anyone willing to single-step through the IL sees immediately which
    /// branch is always taken. Combine with renaming + string encryption
    /// rather than relying on this alone.
    ///
    /// v1 scope: skips methods with exception handlers to avoid fiddly
    /// region-boundary bugs. Flattening the CFG properly (dispatcher loop +
    /// state variable) is a bigger follow-up pass, not attempted here.
    /// </summary>
    public class ControlFlowObfuscator
    {
        private readonly Random _rng = new Random();

        public int JunkBlocksPerMethod { get; set; } = 2;

        public void Process(ModuleDefMD module)
        {
            foreach (var type in module.GetTypes())
            foreach (var method in type.Methods)
            {
                if (method.Body == null) continue;
                if (method.Body.HasExceptionHandlers) continue;
                if (method.Body.Instructions.Count < 4) continue;

                for (int n = 0; n < JunkBlocksPerMethod; n++)
                    InsertOpaquePredicate(module, method.Body);
            }
        }

        private void InsertOpaquePredicate(ModuleDefMD module, CilBody body)
        {
            var instrs = body.Instructions;
            int insertAt = _rng.Next(1, instrs.Count - 1);
            var realTarget = instrs[insertAt];

            // Keep x small enough that x*x can't overflow into a negative
            // int32 — that would break the "always 0 or 1" property.
            int x = _rng.Next(2, 40000);

            var junk = BuildJunkBlock(module, body);
            var junkStart = junk[0];

            var predicate = new List<Instruction>
            {
                Instruction.CreateLdcI4(x),
                Instruction.CreateLdcI4(x),
                Instruction.Create(OpCodes.Mul),   // x*x, always >= 0 in our range
                Instruction.CreateLdcI4(4),
                Instruction.Create(OpCodes.Rem),   // (x*x) % 4 -> always 0 or 1
                Instruction.CreateLdcI4(2),
                Instruction.Create(OpCodes.Ceq),   // == 2 -> always false
                Instruction.Create(OpCodes.Brtrue, junkStart),
                // fall-through = real code (the branch that's always taken)
            };

            for (int i = 0; i < predicate.Count; i++)
                instrs.Insert(insertAt + i, predicate[i]);

            int junkPos = insertAt + predicate.Count;
            foreach (var ji in junk)
                instrs.Insert(junkPos++, ji);

            // Dead branch still needs somewhere valid to go so the method
            // stays verifiable even though this path can never execute.
            instrs.Insert(junkPos, Instruction.Create(OpCodes.Br, realTarget));
        }

        private List<Instruction> BuildJunkBlock(ModuleDefMD module, CilBody body)
        {
            var local = new Local(module.CorLibTypes.Int32);
            body.Variables.Add(local);

            var block = new List<Instruction>();
            int steps = _rng.Next(3, 8);
            for (int i = 0; i < steps; i++)
            {
                block.Add(Instruction.CreateLdcI4(_rng.Next(0, 10000)));
                block.Add(Instruction.CreateLdcI4(_rng.Next(1, 10000)));
                block.Add(Instruction.Create(_rng.Next(2) == 0 ? OpCodes.Add : OpCodes.Xor));
                block.Add(Instruction.Create(OpCodes.Stloc, local));
            }
            return block;
        }
    }
}
