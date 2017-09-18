using System;
using System.Collections.Generic;
using System.Text;

namespace Zip.NetStandard.Crypto
{
    class PBKDF2
    {
        public static PBKDF2 Create()
        {
            return new PBKDF2Cng();
        }

        public virtual byte[] GetBytes(byte[] password, byte[] salt, int iterations, int size)
        {
            Rfc2898DeriveBytesCng rfc2898 = new Rfc2898DeriveBytesCng(password, salt, iterations);

            return rfc2898.GetBytes(size);
        }
    }
}
