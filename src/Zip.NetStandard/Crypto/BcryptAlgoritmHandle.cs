using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace Zip.NetStandard.Crypto
{
    internal class BcryptAlgoritmHandle : IDisposable
    {
        [SuppressUnmanagedCodeSecurity]
        [DllImport("bcrypt.dll", CallingConvention = CallingConvention.Winapi)]
        private static extern int BCryptCloseAlgorithmProvider(
            [In] IntPtr phAlgorithm,
            [In] int dwFlags);

        public IntPtr Handle { get; }

        public BcryptAlgoritmHandle(IntPtr handle)
        {
            Handle = handle;
        }

        private void ReleaseUnmanagedResources()
        {
            BCryptCloseAlgorithmProvider(Handle, 0);
        }

        public void Dispose()
        {
            ReleaseUnmanagedResources();
            GC.SuppressFinalize(this);
        }

        ~BcryptAlgoritmHandle()
        {
            ReleaseUnmanagedResources();
        }
    }
}
