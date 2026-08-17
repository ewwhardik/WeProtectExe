namespace WeProtectExe.Runtime
{
    // This file compiles into its own small assembly (WeProtectExe.Runtime.dll)
    // that gets merged into the protected target BEFORE StringEncryptor runs
    // (e.g. with ILRepack as a pre-pass). Writing this logic as plain C# —
    // instead of hand-assembling a decrypt loop instruction-by-instruction
    // in raw IL — is both easier to get right and easier to audit later.

    internal static class Key
    {
        // Filled in at protect-time by StringEncryptor via an injected call
        // to Init() near the module entry point — see StringEncryptor.cs.
        // Deliberately mutable rather than a `readonly static byte[] = {...}`
        // literal: array-literal fields get compiled to an RVA blob that's
        // trivial to locate and dump; a call-populated field at least makes
        // the key show up in code flow instead of as a flat data blob.
        internal static byte[] Bytes;

        public static void Init(byte[] k) => Bytes = k;
    }

    public static class StrDec
    {
        public static string D(byte[] cipher)
        {
            var key = Key.Bytes;
            var plain = new byte[cipher.Length];
            for (int i = 0; i < cipher.Length; i++)
                plain[i] = (byte)(cipher[i] ^ key[i % key.Length]);
            return System.Text.Encoding.UTF8.GetString(plain);
        }
    }
}
