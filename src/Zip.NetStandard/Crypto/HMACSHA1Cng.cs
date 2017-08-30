using System;
using System.Security.Cryptography;

namespace Zip.NetStandard.Crypto
{
    public class HMACSHA1Cng : HMAC
    {

        public HMACSHA1Cng()
          : this(Utils.GenerateRandom(64))
        {
        }

        public HMACSHA1Cng(byte[] key)
        {
            m_hashName = "SHA1";

            m_hash1 = SHA1.Create("System.Security.Cryptography.SHA1Cng");
            m_hash2 = SHA1.Create("System.Security.Cryptography.SHA1Cng");

            HashSizeValue = 160;
            InitializeKey(key);
        }
    }

    public abstract class HMAC : KeyedHashAlgorithm
    {
        private int blockSizeValue = 64;
        internal string m_hashName;
        internal HashAlgorithm m_hash1;
        internal HashAlgorithm m_hash2;
        private byte[] m_inner;
        private byte[] m_outer;
        private bool m_hashing;

        protected int BlockSizeValue
        {
            get
            {
                return blockSizeValue;
            }
            set
            {
                blockSizeValue = value;
            }
        }

        private void UpdateIOPadBuffers()
        {
            if (m_inner == null)
                m_inner = new byte[BlockSizeValue];
            if (m_outer == null)
                m_outer = new byte[BlockSizeValue];
            for (int index = 0; index < BlockSizeValue; ++index)
            {
                m_inner[index] = 54;
                m_outer[index] = 92;
            }
            for (int index = 0; index < KeyValue.Length; ++index)
            {
                m_inner[index] ^= KeyValue[index];
                m_outer[index] ^= KeyValue[index];
            }
        }

        internal void InitializeKey(byte[] key)
        {
            m_inner = null;
            m_outer = null;
            if (key.Length > BlockSizeValue)
                KeyValue = m_hash1.ComputeHash(key);
            else
                KeyValue = (byte[])key.Clone();
            UpdateIOPadBuffers();
        }

        public override byte[] Key
        {
            get
            {
                return (byte[])KeyValue.Clone();
            }
            set
            {
                if (m_hashing)
                    throw new CryptographicException();
                InitializeKey(value);
            }
        }

        public string HashName
        {
            get
            {
                return m_hashName;
            }
            set
            {
                if (m_hashing)
                    throw new CryptographicException();
                m_hashName = value;
                m_hash1 = HashAlgorithm.Create(m_hashName);
                m_hash2 = HashAlgorithm.Create(m_hashName);
            }
        }

        public override void Initialize()
        {
            m_hash1.Initialize();
            m_hash2.Initialize();
            m_hashing = false;
        }

        protected override void HashCore(byte[] rgb, int ib, int cb)
        {
            if (!m_hashing)
            {
                m_hash1.TransformBlock(m_inner, 0, m_inner.Length, m_inner, 0);
                m_hashing = true;
            }
            m_hash1.TransformBlock(rgb, ib, cb, rgb, ib);
        }

        protected override byte[] HashFinal()
        {
            if (!m_hashing)
            {
                m_hash1.TransformBlock(m_inner, 0, m_inner.Length, m_inner, 0);
                m_hashing = true;
            }
            m_hash1.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            byte[] hashValue = m_hash1.Hash;
            m_hash2.TransformBlock(m_outer, 0, m_outer.Length, m_outer, 0);
            m_hash2.TransformBlock(hashValue, 0, hashValue.Length, hashValue, 0);
            m_hashing = false;
            m_hash2.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            return m_hash2.Hash;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (m_hash1 != null)
                    m_hash1.Dispose();
                if (m_hash2 != null)
                    m_hash2.Dispose();
                if (m_inner != null)
                    Array.Clear(m_inner, 0, m_inner.Length);
                if (m_outer != null)
                    Array.Clear(m_outer, 0, m_outer.Length);
            }
            base.Dispose(disposing);
        }
    }
}
