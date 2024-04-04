using System;
using System.Security.Cryptography;
using System.Text;

public class AesEncryptionExample
{
    public static void Main(string[] args)
    {
        // Text to encrypt
        string originalText = "Hello, world!";
        //p1 aaaabbb
        //same key
        //p2 aaaabbb

        // Generate random key.
        // Encryption Key is used to transform plaintext(unencrypted data) into ciphertext(encrypted data) using encryption process.
        // same key is used to encrypt and decrypt
        //AES - Advanced encrytion standard
        byte[] key = GenerateRandomBytes(16); // 16 bytes for AES-128, 24 bytes for AES-192, 32 bytes for AES-256

        // Generate IV ---its just a random value used along with encryption key to encrypt data securely.
        // to handle case where multiple identical plaintext is getting encrypted.
        // this ensures identical plaintexts with same key produce different cipertext(encrypted text)
        byte[] iv = GenerateRandomBytes(16); // IV is always 16 bytes for AES

        // Encrypt the text
        string encryptedText = Encrypt(originalText, key, iv);
        Console.WriteLine("Encrypted Text: " + encryptedText);

        // Decrypt the text
        string decryptedText = Decrypt(encryptedText, key, iv);
        Console.WriteLine("Decrypted Text: " + decryptedText);
    }

    public static string Encrypt(string plainText, byte[] key, byte[] iv)
    {
        //Aes - Abstract base class for all AES implementations to overwritten.
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.IV = iv;

            // Create an encryptor to perform the stream transform.
            // Symmetric encrypt object.
            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            // Create the streams used for encryption.
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        //ssdsdsdsd
                        //Write all data to the stream.
                        swEncrypt.Write(plainText);
                    }
                    return Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
        }
    }

    public static string Decrypt(string encryptedText, byte[] key, byte[] iv)
    {
        byte[] cipherText = Convert.FromBase64String(encryptedText);

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.IV = iv;

            // Create a decryptor to perform the stream transform.
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            // Create the streams used for decryption.
            using (MemoryStream msDecrypt = new MemoryStream(cipherText))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        // Read the decrypted bytes from the decrypting stream
                        // and place them in a string.
                        return srDecrypt.ReadToEnd();
                    }
                }
            }
        }
    }

    public static byte[] GenerateRandomBytes(int length)
    {
        byte[] randomBytes = new byte[length];
        using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomBytes);
        }
        return randomBytes;
    }
}
