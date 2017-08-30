using System.Security.Cryptography;

namespace Zip.NetStandard.Crypto
{
    static  class Utils
    {
        private static RNGCryptoServiceProvider _rng;

        internal static RNGCryptoServiceProvider StaticRandomNumberGenerator => _rng ?? (_rng = new RNGCryptoServiceProvider());

        internal static byte[] GenerateRandom(int keySize)
        {
            byte[] data = new byte[keySize];
            StaticRandomNumberGenerator.GetBytes(data);
            return data;
        }

        internal static byte[] Int(uint i)
        {
            return new byte[4]
            {
                (byte) (i >> 24),
                (byte) (i >> 16),
                (byte) (i >> 8),
                (byte) i
            };
        }
    }
}
