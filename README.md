# WeProtectExe
### by Hardik Dash

## .NET/C# engine — feature matrix

| Feature | File | What it does |
|---|---|---|
| Symbol renaming | `SymbolRenamer.cs` | Renames non-public types/methods/fields to meaningless identifiers so decompiled output carries no semantic hints |
| String encryption | `StringEncryptor.cs` + `Runtime/StrDec.cs` | Replaces `ldstr` literals with encrypted byte blobs decrypted at runtime — defeats naive string scanning, not a determined analyst with a breakpoint |
| Opaque predicates / junk blocks | `ControlFlowObfuscator.cs` | Inserts always-true branch conditions guarding dead junk code, padding the control-flow graph decompilers show |
| Anti-debug check | `AntiDebugInjector.cs` | Checks `Debugger.IsAttached` at entry and exits if a debugger is attached — one layer, trivially patched by anyone who finds it |

## Building it

```
cd DotNetProtector
dotnet add package dnlib
dotnet build
dotnet run -- input.exe output.exe --rename --strings --cflow --antidebug
```
