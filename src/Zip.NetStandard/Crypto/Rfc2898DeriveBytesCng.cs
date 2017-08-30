using System;
using System.Security.Cryptography;
using System.Text;

namespace Zip.NetStandard.Crypto
{
    public class Rfc2898DeriveBytesCng : DeriveBytes
    {
        private byte[] m_buffer;
        private byte[] m_salt;
        private HMACSHA1Cng m_hmacsha1;
        private byte[] m_password;
        private uint m_iterations;
        private uint m_block;
        private int m_startIndex;
        private int m_endIndex;

        public Rfc2898DeriveBytesCng(string password, int saltSize)
          : this(password, saltSize, 1000)
        {
        }

        public Rfc2898DeriveBytesCng(string password, int saltSize, int iterations)
        {
            if (saltSize < 0)
                throw new ArgumentOutOfRangeException(nameof(saltSize));
            byte[] data = new byte[saltSize];
            Utils.StaticRandomNumberGenerator.GetBytes(data);
            Salt = data;
            IterationCount = iterations;
            m_password = new UTF8Encoding(false).GetBytes(password);
            m_hmacsha1 = new HMACSHA1Cng(m_password);
            Initialize();
        }

        public Rfc2898DeriveBytesCng(string password, byte[] salt)
          : this(password, salt, 1000)
        {
        }

        public Rfc2898DeriveBytesCng(string password, byte[] salt, int iterations)
          : this(new UTF8Encoding(false).GetBytes(password), salt, iterations)
        {
        }

        public Rfc2898DeriveBytesCng(byte[] password, byte[] salt, int iterations)
        {
            Salt = salt;
            IterationCount = iterations;
            m_password = password;
            m_hmacsha1 = new HMACSHA1Cng(password);
            Initialize();
        }

        public int IterationCount
        {
            get
            {
                return (int)m_iterations;
            }
            set
            {
                if (value <= 0)
                    throw new ArgumentOutOfRangeException(nameof(value));
                m_iterations = (uint)value;
                Initialize();
            }
        }

        public byte[] Salt
        {
            get
            {
                return (byte[])m_salt.Clone();
            }
            set
            {
                if (value == null)
                    throw new ArgumentNullException(nameof(value));
                if (value.Length < 8)
                    throw new ArgumentException();
                m_salt = (byte[])value.Clone();
                Initialize();
            }
        }

        public override byte[] GetBytes(int cb)
        {
            if (cb <= 0)
                throw new ArgumentOutOfRangeException(nameof(cb));
            byte[] numArray1 = new byte[cb];
            int dstOffsetBytes = 0;
            int byteCount = m_endIndex - m_startIndex;
            if (byteCount > 0)
            {
                if (cb >= byteCount)
                {
                    Buffer.BlockCopy(m_buffer, m_startIndex, numArray1, 0, byteCount);
                    m_startIndex = m_endIndex = 0;
                    dstOffsetBytes += byteCount;
                }
                else
                {
                    Buffer.BlockCopy(m_buffer, m_startIndex, numArray1, 0, cb);
                    m_startIndex = m_startIndex + cb;
                    return numArray1;
                }
            }
            while (dstOffsetBytes < cb)
            {
                byte[] numArray2 = Func();
                int num1 = cb - dstOffsetBytes;
                if (num1 > 20)
                {
                    Buffer.BlockCopy(numArray2, 0, numArray1, dstOffsetBytes, 20);
                    dstOffsetBytes += 20;
                }
                else
                {
                    Buffer.BlockCopy(numArray2, 0, numArray1, dstOffsetBytes, num1);
                    int num2 = dstOffsetBytes + num1;
                    Buffer.BlockCopy(numArray2, num1, m_buffer, m_startIndex, 20 - num1);
                    m_endIndex = m_endIndex + (20 - num1);
                    return numArray1;
                }
            }
            return numArray1;
        }

        /// <summary>Resets the state of the operation.</summary>
        public override void Reset()
        {
            Initialize();
        }

        /// <summary>Releases the unmanaged resources used by the <see cref="T:System.Security.Cryptography.Rfc2898DeriveBytes" /> class and optionally releases the managed resources.</summary>
        /// <param name="disposing">
        /// <see langword="true" /> to release both managed and unmanaged resources; <see langword="false" /> to release only unmanaged resources. </param>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (!disposing)
                return;
            if (m_hmacsha1 != null)
                m_hmacsha1.Dispose();
            if (m_buffer != null)
                Array.Clear(m_buffer, 0, m_buffer.Length);
            if (m_salt == null)
                return;
            Array.Clear(m_salt, 0, m_salt.Length);
        }

        private void Initialize()
        {
            if (m_buffer != null)
                Array.Clear(m_buffer, 0, m_buffer.Length);
            m_buffer = new byte[20];
            m_block = 1U;
            m_startIndex = m_endIndex = 0;
        }

        private byte[] Func()
        {
            byte[] inputBuffer = Utils.Int(m_block);
            m_hmacsha1.TransformBlock(m_salt, 0, m_salt.Length, null, 0);
            m_hmacsha1.TransformBlock(inputBuffer, 0, inputBuffer.Length, null, 0);
            m_hmacsha1.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            byte[] hashValue = m_hmacsha1.Hash;
            m_hmacsha1.Initialize();
            byte[] numArray = hashValue;
            for (int index1 = 2; (long)index1 <= (long)m_iterations; ++index1)
            {
                m_hmacsha1.TransformBlock(hashValue, 0, hashValue.Length, null, 0);
                m_hmacsha1.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                hashValue = m_hmacsha1.Hash;
                for (int index2 = 0; index2 < 20; ++index2)
                    numArray[index2] ^= hashValue[index2];
                m_hmacsha1.Initialize();
            }
            m_block = m_block + 1U;
            return numArray;
        }
    }
}
