using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class SymmetricCipher
{
    // Генерація криптостійкої випадкової послідовності байтів для Key та IV
    public static byte[] GenerateRandomNumber(int length)
    {
        using (var randomNumberGenerator = RandomNumberGenerator.Create())
        {
            var randomNumber = new byte[length];
            randomNumberGenerator.GetBytes(randomNumber);
            return randomNumber;
        }
    }

    // Універсальний метод зашифрування для будь-якого симетричного алгоритму (DES, TripleDES, AES)
    public static byte[] Encrypt(SymmetricAlgorithm algorithm, byte[] dataToEncrypt, byte[] key, byte[] iv)
    {
        algorithm.Mode = CipherMode.CBC;
        algorithm.Padding = PaddingMode.PKCS7;
        algorithm.Key = key;
        algorithm.IV = iv;

        using (var memoryStream = new MemoryStream())
        {
            using (var cryptoStream = new CryptoStream(memoryStream, algorithm.CreateEncryptor(), CryptoStreamMode.Write))
            {
                cryptoStream.Write(dataToEncrypt, 0, dataToEncrypt.Length);
                cryptoStream.FlushFinalBlock();
                return memoryStream.ToArray();
            }
        }
    }

    // Універсальний метод розшифрування для будь-якого симетричного алгоритму (DES, TripleDES, AES)
    public static byte[] Decrypt(SymmetricAlgorithm algorithm, byte[] dataToDecrypt, byte[] key, byte[] iv)
    {
        algorithm.Mode = CipherMode.CBC;
        algorithm.Padding = PaddingMode.PKCS7;
        algorithm.Key = key;
        algorithm.IV = iv;

        using (var memoryStream = new MemoryStream())
        {
            using (var cryptoStream = new CryptoStream(memoryStream, algorithm.CreateDecryptor(), CryptoStreamMode.Write))
            {
                cryptoStream.Write(dataToDecrypt, 0, dataToDecrypt.Length);
                cryptoStream.FlushFinalBlock();
                return memoryStream.ToArray();
            }
        }
    }
}

class Program
{
    static void TestAlgorithm(string name, SymmetricAlgorithm algorithm, int keySizeBytes, int ivSizeBytes, string plainText)
    {
        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

        // Випадкова генерація секретного ключа та вектора ініціалізації (IV)
        byte[] key = SymmetricCipher.GenerateRandomNumber(keySizeBytes);
        byte[] iv = SymmetricCipher.GenerateRandomNumber(ivSizeBytes);

        // Зашифрування та розшифрування
        byte[] encryptedBytes = SymmetricCipher.Encrypt(algorithm, plainBytes, key, iv);
        byte[] decryptedBytes = SymmetricCipher.Decrypt(algorithm, encryptedBytes, key, iv);

        string decryptedText = Encoding.UTF8.GetString(decryptedBytes);

        Console.WriteLine($"=== Алгоритм: {name} ===");
        Console.WriteLine($"Оригінальний текст : {plainText}");
        Console.WriteLine($"Key ({key.Length,2} байт)      : {Convert.ToBase64String(key)}");
        Console.WriteLine($"IV  ({iv.Length,2} байт)      : {Convert.ToBase64String(iv)}");
        Console.WriteLine($"Зашифровані дані   : {Convert.ToBase64String(encryptedBytes)}");
        Console.WriteLine($"Розшифрований текст: {decryptedText}\n");
    }

    static void Main()
    {
        Console.OutputEncoding = Encoding.UTF8;

        const string originalMessage = "Symmetric encryption test: DES, Triple-DES and AES (Variant 15)";

        // 1. DES: ключ = 8 байтів (64 біти), IV = 8 байтів (64 біти)
        using (var des = DES.Create())
        {
            TestAlgorithm("DES", des, 8, 8, originalMessage);
        }

        // 2. Triple-DES: ключ = 24 байти (192 біти), IV = 8 байтів (64 біти)
        using (var tripleDes = TripleDES.Create())
        {
            TestAlgorithm("Triple-DES", tripleDes, 24, 8, originalMessage);
        }

        // 3. AES: ключ = 32 байти (256 бітів), IV = 16 байтів (128 бітів)
        using (var aes = Aes.Create())
        {
            TestAlgorithm("AES-256", aes, 32, 16, originalMessage);
        }
    }
}