using System;
using System.Runtime.InteropServices;
using System.Security;

namespace Zip.NetStandard.Crypto
{
    class PBKDF2Cng : PBKDF2
    {
        const int BCRYPT_ALG_HANDLE_HMAC_FLAG = 0x00000008;
        const int BCRYPT_HASH_REUSABLE_FLAG   = 0x00000020;

        [SuppressUnmanagedCodeSecurity]
        [DllImport("bcrypt.dll", CallingConvention = CallingConvention.Winapi)]
        private static extern unsafe int BCryptDeriveKeyPBKDF2([In] IntPtr hPrf, [In] byte* pbPassword,
            [In] int cbPassword, [In] byte* pbSalt, [In] int cbSalt, [In] long cIterations, [In] byte* pbDerivedKey,
            [In] int cbDerivedKey, [In] int dwFlags = 0);

        [SuppressUnmanagedCodeSecurity]
        [DllImport("bcrypt.dll", CallingConvention = CallingConvention.Winapi)]
        private static extern int BCryptOpenAlgorithmProvider(
            [Out] out IntPtr phAlgorithm,
            [In, MarshalAs(UnmanagedType.LPWStr)] string pszAlgId,
            [In, MarshalAs(UnmanagedType.LPWStr)] string pszImplementation, 
            [In] int dwFlags);

        private static readonly IntPtr HmacSha1Handle;

        static PBKDF2Cng()
        {
            var code = BCryptOpenAlgorithmProvider(out HmacSha1Handle, "SHA1", null,
                BCRYPT_ALG_HANDLE_HMAC_FLAG | BCRYPT_HASH_REUSABLE_FLAG);
        }

        public override unsafe byte[] GetBytes(byte[] password, byte[] salt, int iterations, int size)
        {
            var result = new byte[size];
            fixed (byte* pwd = password)
            fixed (byte* slt = salt)
            fixed (byte* res = result)
            {
                var code = BCryptDeriveKeyPBKDF2(HmacSha1Handle, pwd, password.Length, slt, salt.Length, iterations, res, size);
            }

            return result;
        }
    }
}
