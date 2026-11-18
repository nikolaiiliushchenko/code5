using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public static class KeyGenerator
{
    // Генерація випадкової «солі» (Salt)
    public static byte[] GenerateRandomSalt(int length)
    {
        using (var rnd = RandomNumberGenerator.Create())
        {
            byte[] salt = new byte[length];
            rnd.GetBytes(salt);
            return salt;
        }
    }

    // Формування секретного ключа (Key) та вектора ініціалізації (IV) із пароля через Rfc2898DeriveBytes
    public static void DeriveKeyAndIvFromPassword(
        string password,
        byte[] salt,
        int iterations,
        int keyByteSize,
        int ivByteSize,
        out byte[] key,
        out byte[] iv)
    {
        using (var rfc2898 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256))
        {
            key = rfc2898.GetBytes(keyByteSize);
            iv = rfc2898.GetBytes(ivByteSize);
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

        const int variant = 15;
        int iterations = variant * 10000; // 15 * 10 000 = 150 000 ітерацій
        const string password = "StudentPassword_Var15";
        const string original = "Конфіденційні дані для шифрування (Варіант 15)";
        byte[] originalBytes = Encoding.UTF8.GetBytes(original);

        // Генеруємо випадкову «сіль» (32 байти)
        byte[] salt = KeyGenerator.GenerateRandomSalt(32);

        Console.WriteLine($"Варіант: {variant} | Кількість ітерацій: {iterations}");
        Console.WriteLine($"Пароль : {password}");
        Console.WriteLine($"Сіль   : {Convert.ToBase64String(salt)}\n");

        // 1. DES з генерацією Key (8 байтів) та IV (8 байтів) із пароля
        KeyGenerator.DeriveKeyAndIvFromPassword(password, salt, iterations, 8, 8, out byte[] desKey, out byte[] desIv);
        var desCipher = new DesCipher();
        byte[] desEncrypted = desCipher.Encrypt(originalBytes, desKey, desIv);
        byte[] desDecrypted = desCipher.Decrypt(desEncrypted, desKey, desIv);

        Console.WriteLine("=== 1. Алгоритм DES (Rfc2898DeriveBytes) ===");
        Console.WriteLine("Key (8 байтів)     : " + Convert.ToBase64String(desKey));
        Console.WriteLine("IV  (8 байтів)     : " + Convert.ToBase64String(desIv));
        Console.WriteLine("Зашифрований текст : " + Convert.ToBase64String(desEncrypted));
        Console.WriteLine("Розшифрований текст: " + Encoding.UTF8.GetString(desDecrypted));
        Console.WriteLine();

        // 2. Triple-DES з генерацією Key (24 байти) та IV (8 байтів) із пароля
        KeyGenerator.DeriveKeyAndIvFromPassword(password, salt, iterations, 24, 8, out byte[] tdesKey, out byte[] tdesIv);
        var tdesCipher = new TripleDesCipher();
        byte[] tdesEncrypted = tdesCipher.Encrypt(originalBytes, tdesKey, tdesIv);
        byte[] tdesDecrypted = tdesCipher.Decrypt(tdesEncrypted, tdesKey, tdesIv);

        Console.WriteLine("=== 2. Алгоритм Triple-DES (Rfc2898DeriveBytes) ===");
        Console.WriteLine("Key (24 байти)     : " + Convert.ToBase64String(tdesKey));
        Console.WriteLine("IV  (8 байтів)     : " + Convert.ToBase64String(tdesIv));
        Console.WriteLine("Зашифрований текст : " + Convert.ToBase64String(tdesEncrypted));
        Console.WriteLine("Розшифрований текст: " + Encoding.UTF8.GetString(tdesDecrypted));
        Console.WriteLine();

        // 3. AES з генерацією Key (32 байти) та IV (16 байтів) із пароля
        KeyGenerator.DeriveKeyAndIvFromPassword(password, salt, iterations, 32, 16, out byte[] aesKey, out byte[] aesIv);
        var aesCipher = new AesCipher();
        byte[] aesEncrypted = aesCipher.Encrypt(originalBytes, aesKey, aesIv);
        byte[] aesDecrypted = aesCipher.Decrypt(aesEncrypted, aesKey, aesIv);

        Console.WriteLine("=== 3. Алгоритм AES-256 (Rfc2898DeriveBytes) ===");
        Console.WriteLine("Key (32 байти)     : " + Convert.ToBase64String(aesKey));
        Console.WriteLine("IV  (16 байтів)    : " + Convert.ToBase64String(aesIv));
        Console.WriteLine("Зашифрований текст : " + Convert.ToBase64String(aesEncrypted));
        Console.WriteLine("Розшифрований текст: " + Encoding.UTF8.GetString(aesDecrypted));
    }
}