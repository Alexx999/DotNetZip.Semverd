using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Zip.NetStandard.Crypto
{
    class PBKDF2Cng : PBKDF2
    {
        const int BCRYPT_ALG_HANDLE_HMAC_FLAG = 0x00000008;
        const int BCRYPT_HASH_REUSABLE_FLAG   = 0x00000020;

        [DllImport("bcrypt.dll", CallingConvention = CallingConvention.Winapi)]
        private static extern unsafe int BCryptDeriveKeyPBKDF2(IntPtr hPrf, byte* pbPassword, int cbPassword, byte* pbSalt, int cbSalt, long cIterations, byte * pbDerivedKey, int cbDerivedKey, int dwFlags = 0);

        [DllImport("bcrypt.dll", CallingConvention = CallingConvention.Winapi)]
        private static extern int BCryptOpenAlgorithmProvider(
            [Out] out IntPtr phAlgorithm,
            [In, MarshalAs(UnmanagedType.LPWStr)] string pszAlgId,
            [In, MarshalAs(UnmanagedType.LPWStr)] string pszImplementation, 
            [In] int dwFlags);

        private static IntPtr hmacSha1Handle;

        static PBKDF2Cng()
        {
            var code = BCryptOpenAlgorithmProvider(out hmacSha1Handle, "SHA1", null,
                BCRYPT_ALG_HANDLE_HMAC_FLAG | BCRYPT_HASH_REUSABLE_FLAG);
        }

        public override unsafe byte[] GetBytes(byte[] password, byte[] salt, int iterations, int size)
        {
            var result = new byte[size];
            fixed (byte* pwd = password)
            fixed (byte* slt = salt)
            fixed (byte* res = result)
            {
                var code = BCryptDeriveKeyPBKDF2(hmacSha1Handle, pwd, password.Length, slt, salt.Length, iterations, res, size);
            }

            return result;
        }
    }
}
