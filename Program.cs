using System;
using dnlib.DotNet;

namespace WeProtectExe.DotNetProtector
{
    class Program
    {
        static int Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine(
                    "WeProtectExe.DotNet\n" +
                    "usage: dotnet run -- <input.exe|dll> <output.exe|dll> [--rename] [--strings] [--cflow] [--antidebug]\n" +
                    "  --rename     rename non-public symbols to meaningless identifiers\n" +
                    "  --strings    encrypt string literals (requires WeProtectExe.Runtime merged in first)\n" +
                    "  --cflow      insert opaque predicates + junk blocks\n" +
                    "  --antidebug  bail out at entry if a debugger is attached"
                );
                return 1;
            }

            string input = args[0];
            string output = args[1];
            bool doRename = HasFlag(args, "--rename");
            bool doStrings = HasFlag(args, "--strings");
            bool doCflow = HasFlag(args, "--cflow");
            bool doAntiDebug = HasFlag(args, "--antidebug");

            var module = ModuleDefMD.Load(input);

            // Order matters: rename before string/cflow passes touch method
            // bodies, so nothing downstream keys off the original names.
            if (doRename)
            {
                Console.WriteLine("[*] Renaming symbols...");
                new SymbolRenamer().Process(module);
            }

            if (doStrings)
            {
                Console.WriteLine("[*] Encrypting strings...");
                new StringEncryptor(RandomKey(16)).Process(module);
            }

            if (doCflow)
            {
                Console.WriteLine("[*] Inserting opaque predicates / junk blocks...");
                new ControlFlowObfuscator { JunkBlocksPerMethod = 3 }.Process(module);
            }

            if (doAntiDebug)
            {
                Console.WriteLine("[*] Injecting anti-debug check...");
                new AntiDebugInjector().Process(module);
            }

            module.Write(output);
            Console.WriteLine($"[+] Protected build written to {output}");
            return 0;
        }

        static bool HasFlag(string[] args, string flag)
        {
            foreach (var a in args)
                if (a.Equals(flag, StringComparison.OrdinalIgnoreCase))
                    return true;
            return false;
        }

        static byte[] RandomKey(int len)
        {
            var key = new byte[len];
            System.Security.Cryptography.RandomNumberGenerator.Fill(key);
            return key;
        }
    }
}
