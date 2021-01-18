using System;
using System.Buffers.Binary;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AeadAes
{
    public class AeadAesCbcSha2
    {
        /***
         * 
         * Implementation of https://tools.ietf.org/id/draft-mcgrew-aead-aes-cbc-hmac-sha2-03.html
         * 
         * ***/

        private static byte[] Version = { 0x01 };
        private static byte[] Separator = { 0x00 };

        public static int BlocksToReadFromStream { set; get; } = 8;
        public enum Algorithm
        {
            AEAD_AES_128_CBC_HMAC_SHA_256,
            AEAD_AES_192_CBC_HMAC_SHA_384,
            AEAD_AES_256_CBC_HMAC_SHA_384,
            AEAD_AES_256_CBC_HMAC_SHA_512
        };

        public static void EncryptStream(Stream inStream, Stream outStream,
    Algorithm algorithm,
    byte[] key,
#nullable enable
            byte[]? additionalAuthenticatedData
    )

        {
            EncryptStream(inStream, outStream, algorithm, key, null, additionalAuthenticatedData);
        }

        public static void EncryptStream(Stream inStream, Stream outStream,
            Algorithm algorithm,
            byte[] key,
#nullable enable
            byte[]? iv,
#nullable enable
            byte[]? additionalAuthenticatedData
            )
        {
            using Aes aes = Aes.Create();
            if (iv != null && (iv.Length * 8) != aes.BlockSize)
            {
                throw new Exception(string.Format("Invalid key length for optional IV = {0} for Algorithm {1}.",
                                iv.Length, algorithm.ToString("g")));

            }

            int enckey_len = 16;
            int mackey_len = 16;
            int autTag_len = 16;

            switch (algorithm)
            {
                case Algorithm.AEAD_AES_128_CBC_HMAC_SHA_256:
                    break;
                case Algorithm.AEAD_AES_192_CBC_HMAC_SHA_384:
                    mackey_len = enckey_len = 24;
                    autTag_len = 24;
                    break;
                case Algorithm.AEAD_AES_256_CBC_HMAC_SHA_384:
                    enckey_len = 32;
                    mackey_len = 24;
                    autTag_len = 24;
                    break;
                case Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512:
                    mackey_len = enckey_len = 32;
                    autTag_len = 32;
                    break;
                default:
                    throw new Exception(string.Format("Invalid Algorithm {0}.", algorithm));
            }

            if (key.Length != (enckey_len + mackey_len))
            {
                throw new Exception(string.Format("Invalid key length {0} for Algorithm {1}.",
                    key.Length, algorithm.ToString("g")));
            }

            byte[] macKey = new byte[mackey_len];
            Array.Copy(key, 0, macKey, 0, mackey_len);
            byte[] encKey = new byte[enckey_len];
            Array.Copy(key, mackey_len, encKey, 0, enckey_len);

            // Ignoring warning for obsolete HMAC constructor as we only use it as a base interface, and not using the obsolete hash version
            HMAC hmac;

            switch (algorithm)
            {
                case Algorithm.AEAD_AES_128_CBC_HMAC_SHA_256:
                    hmac = new HMACSHA256(macKey);
                    break;
                case Algorithm.AEAD_AES_192_CBC_HMAC_SHA_384:
                    hmac = new HMACSHA384(macKey);
                    break;
                case Algorithm.AEAD_AES_256_CBC_HMAC_SHA_384:
                    hmac = new HMACSHA384(macKey);
                    break;
                case Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512:
                    hmac = new HMACSHA512(macKey);
                    break;
                default:
                    throw new Exception(string.Format("Invalid Algorithm {0}.", algorithm));
            }
            Array.Clear(macKey, 0, macKey.Length);

            if (additionalAuthenticatedData != null && (additionalAuthenticatedData.Length > 0))
            {
                hmac.TransformBlock(additionalAuthenticatedData, 0, additionalAuthenticatedData.Length, null, 0);
            }

            aes.Key = encKey;
            Array.Clear(encKey, 0, encKey.Length);
            if (iv == null)
            {
                aes.GenerateIV();
            }
            else
            {
                aes.IV = iv;
            }
            using ICryptoTransform transform = aes.CreateEncryptor();

            // Encrypting by blocks to accomodate for large files.
            int count = 0;
            int offset = 0;

            // blockSizeBytes can be any arbitrary size.
            int blockSizeBytes = BlocksToReadFromStream * (aes.BlockSize / 8);
            byte[] data = new byte[blockSizeBytes];
            int bytesRead = 0;

            byte[] encryptedBlob = new byte[blockSizeBytes];
            Array.Copy(aes.IV, 0, encryptedBlob, 0, aes.IV.Length);
            outStream.Write(encryptedBlob, 0, aes.IV.Length);
            hmac.TransformBlock(encryptedBlob, 0, aes.IV.Length, null, 0);

            bool finalBlockProcessed = false;
            do
            {
                count = inStream.Read(data, 0, blockSizeBytes);
                offset += count;

                if (count > 0)
                {
                    if (count == blockSizeBytes)
                    {
                        int lenc = transform.TransformBlock(data, 0, count, encryptedBlob, 0);
                        outStream.Write(encryptedBlob, 0, lenc);
                    }
                    else
                    {
                        encryptedBlob = transform.TransformFinalBlock(data, 0, count);
                        if (encryptedBlob.Length > 0)
                        {
                            outStream.Write(encryptedBlob, 0, encryptedBlob.Length);
                        }
                        finalBlockProcessed = true;
                    }

                    hmac.TransformBlock(encryptedBlob, 0, encryptedBlob.Length, null, 0);
                    bytesRead += count;
                }
            }
            while (count > 0);

            if (!finalBlockProcessed)
            {
                encryptedBlob = transform.TransformFinalBlock(data, 0, count);
                if (encryptedBlob.Length > 0)
                {
                    outStream.Write(encryptedBlob, 0, encryptedBlob.Length);
                    hmac.TransformBlock(encryptedBlob, 0, encryptedBlob.Length, null, 0);
                }
            }

            Array.Clear(data, 0, data.Length);
            Array.Clear(encryptedBlob, 0, encryptedBlob.Length);

            byte[] aadLen = new byte[8];
            Array.Clear(aadLen, 0, 8);

            if (additionalAuthenticatedData != null && (additionalAuthenticatedData.Length > 0))
            {
                BinaryPrimitives.WriteUInt64BigEndian(aadLen, (UInt64)(additionalAuthenticatedData.Length * 8));
            }

            hmac.TransformFinalBlock(aadLen, 0, aadLen.Length);

            if (hmac.HashSize >= autTag_len
                && hmac.Hash != null // This check is unecessary since we check the HashSize property, but the compiler may throw a warning otherwise
                )
            {
                outStream.Write(hmac.Hash, 0, autTag_len);
            }
            else
            {
                throw new Exception("HMAC could not be calculated.");
            }

            hmac.Dispose();
        }

        public static void DecryptStream(Stream inStream, Stream outStream,
    Algorithm algorithm,
    byte[] key,
#nullable enable
    byte[]? additionalAuthenticatedData
)
        {
            using Aes aes = Aes.Create();

            // Ignoring warning for obsolete HMAC constructor as we only use it as a base interface, and not using the obsolete hash version
            int enckey_len = 16;
            int mackey_len = 16;
            int autTag_len = 16;

            switch (algorithm)
            {
                case Algorithm.AEAD_AES_128_CBC_HMAC_SHA_256:
                    break;
                case Algorithm.AEAD_AES_192_CBC_HMAC_SHA_384:
                    mackey_len = enckey_len = 24;
                    autTag_len = 24;
                    break;
                case Algorithm.AEAD_AES_256_CBC_HMAC_SHA_384:
                    enckey_len = 32;
                    mackey_len = 24;
                    autTag_len = 24;
                    break;
                case Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512:
                    mackey_len = enckey_len = 32;
                    autTag_len = 32;
                    break;
                default:
                    throw new Exception(string.Format("Invalid Algorithm {0}.", algorithm));
            }

            if (key.Length != (enckey_len + mackey_len))
            {
                throw new Exception(string.Format("Invalid key length {0} for Algorithm {1}.",
                    key.Length, algorithm.ToString("g")));
            }

            byte[] macKey = new byte[mackey_len];
            Array.Copy(key, 0, macKey, 0, mackey_len);
            byte[] encKey = new byte[enckey_len];
            Array.Copy(key, mackey_len, encKey, 0, enckey_len);

            // Ignoring warning for obsolete HMAC constructor as we only use it as a base interface, and not using the obsolete hash version
            HMAC hmac;

            switch (algorithm)
            {
                case Algorithm.AEAD_AES_128_CBC_HMAC_SHA_256:
                    hmac = new HMACSHA256(macKey);
                    break;
                case Algorithm.AEAD_AES_192_CBC_HMAC_SHA_384:
                    hmac = new HMACSHA384(macKey);
                    break;
                case Algorithm.AEAD_AES_256_CBC_HMAC_SHA_384:
                    hmac = new HMACSHA384(macKey);
                    break;
                case Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512:
                    hmac = new HMACSHA512(macKey);
                    break;
                default:
                    throw new Exception(string.Format("Invalid Algorithm {0}.", algorithm));
            }
            Array.Clear(macKey, 0, macKey.Length);

            if (additionalAuthenticatedData != null && (additionalAuthenticatedData.Length > 0))
            {
                hmac.TransformBlock(additionalAuthenticatedData, 0, additionalAuthenticatedData.Length, null, 0);
            }

            byte[] mac = new byte[autTag_len];

            long initalPos = inStream.Position;

            long macPos = inStream.Length - autTag_len;

            inStream.Position = macPos;

            inStream.Read(mac);

            inStream.Position = initalPos;
            long cLen = macPos - initalPos;

            // Encrypting by blocks to accomodate for large files.
            int count = 0;
            int offset = 0;

            // blockSizeBytes can be any arbitrary size.
            int blockSizeBytes = BlocksToReadFromStream * (aes.BlockSize / 8);
            byte[] data = new byte[blockSizeBytes];
            long bytesRead = 0;

            byte[] decryptedBlob = new byte[blockSizeBytes];
            bool endOfRead = false;

            do
            {
                Array.Clear(data, 0, data.Length);
                count = inStream.Read(data, 0, blockSizeBytes);
                offset += count;

                bytesRead += count;

                if (bytesRead > cLen)
                {
                    count = count - (int)(bytesRead - cLen);
                    endOfRead = true;
                }

                if (count > 0)
                {
                    hmac.TransformBlock(data, 0, count, null, 0);
                }
            }
            while (count > 0 && !endOfRead);

            byte[] aadLen = new byte[8];
            Array.Clear(aadLen, 0, 8);

            if (additionalAuthenticatedData != null && (additionalAuthenticatedData.Length > 0))
            {
                BinaryPrimitives.WriteUInt64BigEndian(aadLen, (UInt64)(additionalAuthenticatedData.Length * 8));
            }

            hmac.TransformFinalBlock(aadLen, 0, aadLen.Length);

            if (hmac.HashSize < autTag_len
                || hmac.Hash == null // This check is unecessary since we check the HashSize property, but the compiler may throw a warning otherwise
                )
            {
                throw new Exception("Invalid calculated Hash");
            }

            byte[] calculatedMac = new byte[autTag_len];
            Array.Copy(hmac.Hash, calculatedMac, autTag_len);

            if (!mac.SequenceEqual(calculatedMac))
            {
                throw new Exception("Authentication tag does match.");
            }

            hmac.Dispose();

            aes.Key = encKey;
            Array.Clear(encKey, 0, encKey.Length);
            byte[] iv = new byte[aes.BlockSize / 8];

            inStream.Position = initalPos;
            inStream.Read(iv, 0, iv.Length);
            aes.IV = iv;

            using ICryptoTransform transform = aes.CreateDecryptor();

            offset = (int)initalPos + (aes.BlockSize / 8);
            bytesRead = 0;
            cLen -= (aes.BlockSize / 8);
            do
            {
                count = inStream.Read(data, 0, blockSizeBytes);
                bytesRead += count;

                if (count > 0)
                {
                    if (bytesRead > cLen)
                    {
                        count = count - (int)(bytesRead - cLen);
                    }
                    offset += count;

                    if (offset < macPos)
                    {
                        int dec = transform.TransformBlock(data, 0, count, decryptedBlob, 0);
                        outStream.Write(decryptedBlob, 0, dec);
                        Array.Clear(decryptedBlob, 0, decryptedBlob.Length);
                    }
                    else
                    {
                        byte[] final = transform.TransformFinalBlock(data, 0, count);
                        if (final != null && final.Length > 0)
                        {
                            outStream.Write(final, 0, final.Length);
                        }
                    }
                }
            }
            while (count > 0);

            Array.Clear(data, 0, data.Length);
        }
    }
}
