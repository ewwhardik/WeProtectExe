using System;
using System.Text;
using dnlib.DotNet;

namespace WeProtectExe.DotNetProtector
{
    /// <summary>
    /// Renames private/internal symbols to meaningless identifiers so
    /// decompiled output (ILSpy/dnSpy) carries no semantic hints about what
    /// a class, method, or field actually does. Public API surface (things
    /// other assemblies or reflection depend on) is left alone unless you
    /// explicitly opt in — breaking your own public contract by accident is
    /// the single most common way people brick their app with a renamer.
    ///
    /// Tag anything you need to keep readable (e.g. types referenced only
    /// via reflection/serialization) with a [Keep] attribute defined in
    /// your own project — this pass checks for a type named
    /// "WeProtectExe.KeepAttribute" by full name so it has no hard
    /// dependency on your assembly.
    /// </summary>
    public class SymbolRenamer
    {
        private readonly Random _rng = new Random();

        public bool RenamePublicMembers { get; set; } = false;

        public void Process(ModuleDefMD module)
        {
            foreach (var type in module.GetTypes())
            {
                if (type.IsGlobalModuleType) continue;
                if (!RenamePublicMembers && IsPubliclyVisible(type)) continue;
                if (HasKeepAttribute(type)) continue;

                type.Name = NextName("T");
                if (!string.IsNullOrEmpty(type.Namespace))
                    type.Namespace = NextName("N");

                foreach (var method in type.Methods)
                {
                    if (method.IsConstructor || method.IsStaticConstructor) continue;
                    if (!RenamePublicMembers && IsPubliclyVisible(method)) continue;
                    if (HasKeepAttribute(method)) continue;
                    method.Name = NextName("M");
                }

                foreach (var field in type.Fields)
                {
                    if (!RenamePublicMembers && IsPubliclyVisible(field)) continue;
                    if (HasKeepAttribute(field)) continue;
                    field.Name = NextName("F");
                }
            }
        }

        private static bool IsPubliclyVisible(TypeDef t) => t.IsPublic || t.IsNestedPublic;
        private static bool IsPubliclyVisible(MethodDef m) => m.IsPublic;
        private static bool IsPubliclyVisible(FieldDef f) => f.IsPublic;

        private static bool HasKeepAttribute(IHasCustomAttribute member)
        {
            foreach (var ca in member.CustomAttributes)
                if (ca.TypeFullName == "WeProtectExe.KeepAttribute") return true;
            return false;
        }

        private UTF8String NextName(string prefix)
        {
            var bytes = new byte[6];
            _rng.NextBytes(bytes);
            var sb = new StringBuilder(prefix);
            sb.Append('_');
            foreach (var b in bytes) sb.Append(b.ToString("x2"));
            return new UTF8String(sb.ToString());
        }
    }
}
