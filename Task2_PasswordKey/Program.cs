using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class PasswordBasedCipher
{
    // Генерація випадкової «солі» (32 байти)
    public static byte[] GenerateSalt()
    {
        using (var rng = RandomNumberGenerator.Create())
        {
            byte[] salt = new byte[32];
            rng.GetBytes(salt);
            return salt;
        }
    }

    // Зашифрування з формуванням Key та IV із пароля через Rfc2898DeriveBytes
    public static byte[] EncryptWithPassword(
        SymmetricAlgorithm algorithm,
        byte[] dataToEncrypt,
        string password,
        byte[] salt,
        int iterations,
        int keyByteLength,
        int ivByteLength,
        out byte[] generatedKey,
        out byte[] generatedIv)
    {
        using (var rfc2898 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256))
        {
            generatedKey = rfc2898.GetBytes(keyByteLength);
            generatedIv = rfc2898.GetBytes(ivByteLength);
        }

        algorithm.Mode = CipherMode.CBC;
        algorithm.Padding = PaddingMode.PKCS7;
        algorithm.Key = generatedKey;
        algorithm.IV = generatedIv;

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

    // Розшифрування з відновленням тих самих Key та IV із пароля та солі через Rfc2898DeriveBytes
    public static byte[] DecryptWithPassword(
        SymmetricAlgorithm algorithm,
        byte[] dataToDecrypt,
        string password,
        byte[] salt,
        int iterations,
        int keyByteLength,
        int ivByteLength)
    {
        byte[] derivedKey;
        byte[] derivedIv;

        using (var rfc2898 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256))
        {
            derivedKey = rfc2898.GetBytes(keyByteLength);
            derivedIv = rfc2898.GetBytes(ivByteLength);
        }

        algorithm.Mode = CipherMode.CBC;
        algorithm.Padding = PaddingMode.PKCS7;
        algorithm.Key = derivedKey;
        algorithm.IV = derivedIv;

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
    static void TestPasswordAlgorithm(
        string name,
        SymmetricAlgorithm algorithm,
        int keySizeBytes,
        int ivSizeBytes,
        string plainText,
        string password,
        int iterations)
    {
        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
        byte[] salt = PasswordBasedCipher.GenerateSalt();

        // 1. Зашифрування на основі пароля та солі
        byte[] encryptedBytes = PasswordBasedCipher.EncryptWithPassword(
            algorithm,
            plainBytes,
            password,
            salt,
            iterations,
            keySizeBytes,
            ivSizeBytes,
            out byte[] key,
            out byte[] iv);

        // 2. Розшифрування на основі того самого пароля, солі та числа ітерацій
        byte[] decryptedBytes = PasswordBasedCipher.DecryptWithPassword(
            algorithm,
            encryptedBytes,
            password,
            salt,
            iterations,
            keySizeBytes,
            ivSizeBytes);

        string decryptedText = Encoding.UTF8.GetString(decryptedBytes);

        Console.WriteLine($"=== Алгоритм: {name} (PBKDF2 / Rfc2898DeriveBytes) ===");
        Console.WriteLine($"Пароль             : {password}");
        Console.WriteLine($"Кількість ітерацій : {iterations}");
        Console.WriteLine($"Сіль (32 байти)    : {Convert.ToBase64String(salt)}");
        Console.WriteLine($"Похідний Key ({key.Length,2} б): {Convert.ToBase64String(key)}");
        Console.WriteLine($"Похідний IV  ({iv.Length,2} б): {Convert.ToBase64String(iv)}");
        Console.WriteLine($"Зашифровані дані   : {Convert.ToBase64String(encryptedBytes)}");
        Console.WriteLine($"Розшифрований текст: {decryptedText}\n");
    }

    static void Main()
    {
        Console.OutputEncoding = Encoding.UTF8;

        const int variant = 15;
        int iterations = variant * 10000; // 15 * 10 000 = 150 000 ітерацій
        const string password = "StrongPassword_Variant15!";
        const string message = "Secret message protected by password-derived Key and IV!";

        Console.WriteLine($"Варіант {variant}: число ітерацій = {variant} * 10 000 = {iterations}\n");

        // 1. DES з генерацією ключа (8 байт) та IV (8 байт) із пароля
        using (var des = DES.Create())
        {
            TestPasswordAlgorithm("DES", des, 8, 8, message, password, iterations);
        }

        // 2. Triple-DES з генерацією ключа (24 байти) та IV (8 байт) із пароля
        using (var tripleDes = TripleDES.Create())
        {
            TestPasswordAlgorithm("Triple-DES", tripleDes, 24, 8, message, password, iterations);
        }

        // 3. AES з генерацією ключа (32 байти) та IV (16 байт) із пароля
        using (var aes = Aes.Create())
        {
            TestPasswordAlgorithm("AES-256", aes, 32, 16, message, password, iterations);
        }
    }
}