using System;
using System.Text;
using System.Security.Cryptography;
namespace RSAPwd
{
    public class RSA
    {
        RSAParameters privateKey;

        public string PrivateKey
        {
            get { return rsa.ToXmlString(true); }
        }
        RSAParameters publicKey;

        public string PublicKey
        {
            get { return rsa.ToXmlString(false); }
        }
        RSACryptoServiceProvider rsa;
        public RSA()
        {
            rsa = new RSACryptoServiceProvider();
            privateKey = rsa.ExportParameters(true);
            publicKey = rsa.ExportParameters(false);
        }
        public RSA(string key)
        {
            rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(key);
            privateKey = rsa.ExportParameters(true);
            publicKey = rsa.ExportParameters(false);
        }
        public string Encrypt(string stringDataToEncrypt)
        {
            byte[] encryptedData = RSAHelper.RsaEncrypt(Encoding.Unicode.GetBytes(stringDataToEncrypt), publicKey.Exponent, publicKey.Modulus);
            return Convert.ToBase64String(encryptedData);
        }
        public string Decrypt(string encryptedBase64String)
        {
            byte[] encryptedData = RSAHelper.RsaDecrypt(Convert.FromBase64String(encryptedBase64String), privateKey.D, privateKey.Modulus);
            return Encoding.Unicode.GetString(encryptedData);
        }
    }
    public static class RSAHelper
    {

        public static RSAParameters ConvertFromPemPublicKey(string pemFileConent)
        {
            if (string.IsNullOrEmpty(pemFileConent))
            {
                throw new ArgumentNullException("pemFileConent", "This arg cann't be empty.");
            }
            pemFileConent = pemFileConent.Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "").Replace("\n", "").Replace("\r", "");
            byte[] array = Convert.FromBase64String(pemFileConent);
            bool flag = array.Length == 162;
            byte[] array2 = flag ? new byte[128] : new byte[256];
            byte[] array3 = new byte[3];
            Array.Copy(array, flag ? 29 : 33, array2, 0, flag ? 128 : 256);
            Array.Copy(array, flag ? 159 : 291, array3, 0, 3);
            return new RSAParameters
            {
                Modulus = array2,
                Exponent = array3
            };
        }

        public static RSAParameters ConvertFromPemPrivateKey(string pemFileConent)
        {
            if (string.IsNullOrEmpty(pemFileConent))
            {
                throw new ArgumentNullException("pemFileConent", "This arg cann't be empty.");
            }
            pemFileConent = pemFileConent.Replace("-----BEGIN RSA PRIVATE KEY-----", "").Replace("-----END RSA PRIVATE KEY-----", "").Replace("\n", "").Replace("\r", "");
            byte[] array = Convert.FromBase64String(pemFileConent);
            bool flag = array.Length == 609 || array.Length == 610;
            int num = flag ? 11 : 12;
            byte[] array2 = flag ? new byte[128] : new byte[256];
            Array.Copy(array, num, array2, 0, array2.Length);
            num += array2.Length;
            num += 2;
            byte[] array3 = new byte[3];
            Array.Copy(array, num, array3, 0, 3);
            num += 3;
            num += 4;
            if (array[num] == 0)
            {
                num++;
            }
            byte[] array4 = flag ? new byte[128] : new byte[256];
            Array.Copy(array, num, array4, 0, array4.Length);
            num += array4.Length;
            num += (flag ? ((array[num + 1] == 64) ? 2 : 3) : ((array[num + 2] == 128) ? 3 : 4));
            byte[] array5 = flag ? new byte[64] : new byte[128];
            Array.Copy(array, num, array5, 0, array5.Length);
            num += array5.Length;
            num += (flag ? ((array[num + 1] == 64) ? 2 : 3) : ((array[num + 2] == 128) ? 3 : 4));
            byte[] array6 = flag ? new byte[64] : new byte[128];
            Array.Copy(array, num, array6, 0, array6.Length);
            num += array6.Length;
            num += (flag ? ((array[num + 1] == 64) ? 2 : 3) : ((array[num + 2] == 128) ? 3 : 4));
            byte[] array7 = flag ? new byte[64] : new byte[128];
            Array.Copy(array, num, array7, 0, array7.Length);
            num += array7.Length;
            num += (flag ? ((array[num + 1] == 64) ? 2 : 3) : ((array[num + 2] == 128) ? 3 : 4));
            byte[] array8 = flag ? new byte[64] : new byte[128];
            Array.Copy(array, num, array8, 0, array8.Length);
            num += array8.Length;
            num += (flag ? ((array[num + 1] == 64) ? 2 : 3) : ((array[num + 2] == 128) ? 3 : 4));
            byte[] array9 = flag ? new byte[64] : new byte[128];
            Array.Copy(array, num, array9, 0, array9.Length);
            return new RSAParameters
            {
                Modulus = array2,
                Exponent = array3,
                D = array4,
                P = array5,
                Q = array6,
                DP = array7,
                DQ = array8,
                InverseQ = array9
            };
        }

        /// <summary>
        /// RSAs the encrypt.
        /// </summary>
        /// <param name="datatoencrypt">The datatoencrypt.</param>
        /// <param name="exponent">The exponent.</param>
        /// <param name="modulus">The modulus.</param>
        /// <returns></returns>
        public static byte[] RsaEncrypt(byte[] datatoencrypt, byte[] exponent, byte[] modulus)
        {
            var original = new BigInteger(datatoencrypt);
            var e = new BigInteger(exponent);
            var n = new BigInteger(modulus);
            var encrypted = original.modPow(e, n);
            return encrypted.getBytes();
        }

        /// <summary>
        /// RSAs the decrypt.
        /// </summary>
        /// <param name="encrypteddata">The encrypteddata.</param>
        /// <param name="d">The d.</param>
        /// <param name="modulus">The modulus.</param>
        /// <returns></returns>
        public static byte[] RsaDecrypt(byte[] encrypteddata, byte[] d, byte[] modulus)
        {
            var encrypted = new BigInteger(encrypteddata);
            var dd = new BigInteger(d);
            var n = new BigInteger(modulus);
            var decrypted = encrypted.modPow(dd, n);
            return decrypted.getBytes();
        }

        /// <summary>
        /// Generate random bytes with given length
        /// </summary>
        /// <param name="bytelength"></param>
        /// <returns></returns>
        public static byte[] GenerateRandomBytes(int bytelength)
        {
            var buff = new byte[bytelength];
            var rng = new RNGCryptoServiceProvider();

            rng.GetBytes(buff);
            return buff;
        }

    }
    public static class DataTranslate
    {
        public static byte[] HexStringToByte(String hex)
        {
            int len = (hex.Length / 2);
            byte[] result = new byte[len];
            char[] achar = hex.ToCharArray();
            for (int i = 0; i < len; i++)
            {
                int pos = i * 2;
                result[i] = (byte)(ToByte(achar[pos]) << 4 | ToByte(achar[pos + 1]));
            }
            return result;
        }
        private static byte ToByte(char c)
        {
            byte b = (byte)"0123456789ABCDEF".IndexOf(c);
            return b;
        }
        public static String BytesToHexString(byte[] bytes)
        {
            StringBuilder sb = new StringBuilder(bytes.Length);
            String sTemp;
            for (int i = 0; i < bytes.Length; i++)
            {
                sTemp = bytes[i].ToString("x");
                if (sTemp.Length < 2)
                    sb.Append(0);
                sb.Append(sTemp.ToUpper());
            }
            return sb.ToString();
        }
    }
}