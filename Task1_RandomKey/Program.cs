using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public static class SecureRandomGenerator
{
    public static byte[] GenerateRndBytes(int length)
    {
        using (var rnd = RandomNumberGenerator.Create())
        {
            byte[] random = new byte[length];
            rnd.GetBytes(random);
            return random;
        }
    }
}

internal class DesCipher
{
    public byte[] Encrypt(byte[] dataToEncrypt, byte[] key, byte[] iv)
    {
        using (DES desAlg = DES.Create())
        {
            desAlg.Key = key;
            desAlg.IV = iv;

            ICryptoTransform encryptor = desAlg.CreateEncryptor(desAlg.Key, desAlg.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    csEncrypt.Write(dataToEncrypt, 0, dataToEncrypt.Length);
                    csEncrypt.FlushFinalBlock();
                    return msEncrypt.ToArray();
                }
            }
        }
    }

    public byte[] Decrypt(byte[] dataToDecrypt, byte[] key, byte[] iv)
    {
        using (DES desAlg = DES.Create())
        {
            desAlg.Key = key;
            desAlg.IV = iv;

            ICryptoTransform decryptor = desAlg.CreateDecryptor(desAlg.Key, desAlg.IV);

            using (MemoryStream msDecrypt = new MemoryStream(dataToDecrypt))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (MemoryStream msPlain = new MemoryStream())
                    {
                        csDecrypt.CopyTo(msPlain);
                        return msPlain.ToArray();
                    }
                }
            }
        }
    }
}

internal class TripleDesCipher
{
    public byte[] Encrypt(byte[] dataToEncrypt, byte[] key, byte[] iv)
    {
        using (TripleDES tdesAlg = TripleDES.Create())
        {
            tdesAlg.Key = key;
            tdesAlg.IV = iv;

            ICryptoTransform encryptor = tdesAlg.CreateEncryptor(tdesAlg.Key, tdesAlg.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    csEncrypt.Write(dataToEncrypt, 0, dataToEncrypt.Length);
                    csEncrypt.FlushFinalBlock();
                    return msEncrypt.ToArray();
                }
            }
        }
    }

    public byte[] Decrypt(byte[] dataToDecrypt, byte[] key, byte[] iv)
    {
        using (TripleDES tdesAlg = TripleDES.Create())
        {
            tdesAlg.Key = key;
            tdesAlg.IV = iv;

            ICryptoTransform decryptor = tdesAlg.CreateDecryptor(tdesAlg.Key, tdesAlg.IV);

            using (MemoryStream msDecrypt = new MemoryStream(dataToDecrypt))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (MemoryStream msPlain = new MemoryStream())
                    {
                        csDecrypt.CopyTo(msPlain);
                        return msPlain.ToArray();
                    }
                }
            }
        }
    }
}

internal class AesCipher
{
    public byte[] Encrypt(byte[] dataToEncrypt, byte[] key, byte[] iv)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.IV = iv;

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    csEncrypt.Write(dataToEncrypt, 0, dataToEncrypt.Length);
                    csEncrypt.FlushFinalBlock();
                    return msEncrypt.ToArray();
                }
            }
        }
    }

    public byte[] Decrypt(byte[] dataToDecrypt, byte[] key, byte[] iv)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.IV = iv;

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msDecrypt = new MemoryStream(dataToDecrypt))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (MemoryStream msPlain = new MemoryStream())
                    {
                        csDecrypt.CopyTo(msPlain);
                        return msPlain.ToArray();
                    }
                }
            }
        }
    }
}

class Program
{
    static void Main()
    {
        Console.OutputEncoding = Encoding.UTF8;
        const string original = "Конфіденційні дані для шифрування (Варіант 15)";
        byte[] originalBytes = Encoding.UTF8.GetBytes(original);

        // 1. DES (ключ = 8 байтів, вектор ініціалізації IV = 8 байтів)
        var desCipher = new DesCipher();
        byte[] desKey = SecureRandomGenerator.GenerateRndBytes(8);
        byte[] desIv = SecureRandomGenerator.GenerateRndBytes(8);

        byte[] desEncrypted = desCipher.Encrypt(originalBytes, desKey, desIv);
        byte[] desDecrypted = desCipher.Decrypt(desEncrypted, desKey, desIv);

        Console.WriteLine("=== 1. Алгоритм DES (випадкові Key та IV) ===");
        Console.WriteLine("Вихідний текст     : " + original);
        Console.WriteLine("Key (8 байтів)     : " + Convert.ToBase64String(desKey));
        Console.WriteLine("IV  (8 байтів)     : " + Convert.ToBase64String(desIv));
        Console.WriteLine("Зашифрований текст : " + Convert.ToBase64String(desEncrypted));
        Console.WriteLine("Розшифрований текст: " + Encoding.UTF8.GetString(desDecrypted));
        Console.WriteLine();

        // 2. Triple-DES (ключ = 24 байти, вектор ініціалізації IV = 8 байтів)
        var tdesCipher = new TripleDesCipher();
        byte[] tdesKey = SecureRandomGenerator.GenerateRndBytes(24);
        byte[] tdesIv = SecureRandomGenerator.GenerateRndBytes(8);

        byte[] tdesEncrypted = tdesCipher.Encrypt(originalBytes, tdesKey, tdesIv);
        byte[] tdesDecrypted = tdesCipher.Decrypt(tdesEncrypted, tdesKey, tdesIv);

        Console.WriteLine("=== 2. Алгоритм Triple-DES (випадкові Key та IV) ===");
        Console.WriteLine("Вихідний текст     : " + original);
        Console.WriteLine("Key (24 байти)     : " + Convert.ToBase64String(tdesKey));
        Console.WriteLine("IV  (8 байтів)     : " + Convert.ToBase64String(tdesIv));
        Console.WriteLine("Зашифрований текст : " + Convert.ToBase64String(tdesEncrypted));
        Console.WriteLine("Розшифрований текст: " + Encoding.UTF8.GetString(tdesDecrypted));
        Console.WriteLine();

        // 3. AES (ключ = 32 байти, вектор ініціалізації IV = 16 байтів)
        var aesCipher = new AesCipher();
        byte[] aesKey = SecureRandomGenerator.GenerateRndBytes(32);
        byte[] aesIv = SecureRandomGenerator.GenerateRndBytes(16);

        byte[] aesEncrypted = aesCipher.Encrypt(originalBytes, aesKey, aesIv);
        byte[] aesDecrypted = aesCipher.Decrypt(aesEncrypted, aesKey, aesIv);

        Console.WriteLine("=== 3. Алгоритм AES-256 (випадкові Key та IV) ===");
        Console.WriteLine("Вихідний текст     : " + original);
        Console.WriteLine("Key (32 байти)     : " + Convert.ToBase64String(aesKey));
        Console.WriteLine("IV  (16 байтів)    : " + Convert.ToBase64String(aesIv));
        Console.WriteLine("Зашифрований текст : " + Convert.ToBase64String(aesEncrypted));
        Console.WriteLine("Розшифрований текст: " + Encoding.UTF8.GetString(aesDecrypted));
    }
}