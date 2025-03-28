using System.Security.Cryptography;

namespace Digoso.EncryptionDemo;

public class DecryptionService
{
    private const int KeySize = 512;
    private const int SignatureSize = KeySize;


    private readonly IRSAKeyProvider _keyProvider;

    public DecryptionService(IRSAKeyProvider keyProvider)
    {
        _keyProvider = keyProvider;
    }

    /// <summary>
    /// Entschlüsselt und überprüft eine Datei
    /// </summary>
    /// <param name="inputStream">Stream der verschlüsselten Datei</param>
    /// <param name="outputStream">Stream der entschlüsselten Datei</param>
    public void Decrypt(Stream inputStream, Stream outputStream)
    {
        RSA rsaPrivate = _keyProvider.GetRSAPrivateKey();

        Span<byte> encryptedKey = new byte[KeySize];
        Span<byte> encryptedIV = new byte[KeySize];

        inputStream.ReadExactly(encryptedKey);
        inputStream.ReadExactly(encryptedIV);

        // ReadFully(inputStream, encryptedKey);
        // ReadFully(inputStream, encryptedIV);

        byte[] aesKey = rsaPrivate.Decrypt(encryptedKey, RSAEncryptionPadding.OaepSHA256);
        byte[] aesIV = rsaPrivate.Decrypt(encryptedIV, RSAEncryptionPadding.OaepSHA256);

        using var encryptedDataStream = new MemoryStream();
        inputStream.CopyTo(encryptedDataStream);
        encryptedDataStream.Seek(0, SeekOrigin.Begin);

        long dataLength = encryptedDataStream.Length - SignatureSize;
        byte[] encryptedData = new byte[dataLength];
        byte[] signature = new byte[SignatureSize];

        encryptedDataStream.Read(encryptedData, 0, encryptedData.Length);
        encryptedDataStream.Read(signature, 0, signature.Length);

        if (!VerifyData(new MemoryStream(encryptedData), signature, rsaPrivate))
        {
            throw new CryptographicException("Invalid signature");
        }

        byte[] decryptedData = DecryptWithAES(encryptedData, aesKey, aesIV);
        outputStream.Write(decryptedData, 0, decryptedData.Length);
    }


    /// <summary>
    /// Entschlüsselt Daten mit AES
    /// </summary>
    /// <param name="data">Zu entschlüsselnde Daten</param>
    /// <param name="key">AES-Schlüssel</param>
    /// <param name="iv">Initialisierungsvektor</param>
    /// <returns>Entschlüsselte Daten</returns>
    private byte[] DecryptWithAES(byte[] data, byte[] key, byte[] iv)
    {
        using (Aes aes = Aes.Create())
        {
            aes.KeySize = 256;
            aes.Key = key;
            aes.IV = iv;

            using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
            using (MemoryStream ms = new MemoryStream(data))
            using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
            using (MemoryStream output = new MemoryStream())
            {
                cs.CopyTo(output);
                return output.ToArray();
            }
        }
    }

    /// <summary>
    /// Überprüft die Signatur der Daten mit RSA
    /// </summary>
    /// <param name="data">Zu überprüfende Daten</param>
    /// <param name="signature">Signatur</param>
    /// <param name="rsa">RSA-Schlüssel zum Überprüfen</param>
    /// <returns>True, wenn die Signatur gültig ist, sonst False</returns>
    private bool VerifyData(Stream stream, byte[] signature, RSA rsa)
    {
        using SHA256 sha256 = SHA256.Create();
        byte[] hash = sha256.ComputeHash(stream);
        return rsa.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }
}
