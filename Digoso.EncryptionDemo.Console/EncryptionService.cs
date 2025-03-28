using System.Security.Cryptography;

namespace Digoso.EncryptionDemo;

public class EncryptionService
{
    private const int AesKeySize = 256;

    private readonly IRSAKeyProvider _keyProvider;

    public EncryptionService(IRSAKeyProvider keyProvider)
    {
        _keyProvider = keyProvider;
    }

    /// <summary>
    /// Verschlüsselt und signiert eine Datei
    /// </summary>
    /// <param name="inputStream">Stream der Eingabedatei</param>
    /// <param name="outputStream">Stream der Ausgabedatei</param>
    public void Encrypt(Stream inputStream, Stream outputStream)
    {
        (byte[] aesKey, byte[] aesIV) = GenerateAesKeyAndIV();

        RSA rsaPublic = _keyProvider.GetRSAPublicKey();
        RSA rsaPrivate = _keyProvider.GetRSAPrivateKey();

        byte[] encryptedKey = rsaPublic.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA256);
        byte[] encryptedIV = rsaPublic.Encrypt(aesIV, RSAEncryptionPadding.OaepSHA256);

        using var tempStream = new MemoryStream();
        EncryptStreamWithAes(inputStream, tempStream, aesKey, aesIV);
        tempStream.Seek(0, SeekOrigin.Begin);

        byte[] signature = CreateSignatureForStream(tempStream, rsaPrivate);
        tempStream.Seek(0, SeekOrigin.Begin);

        outputStream.Write(encryptedKey, 0, encryptedKey.Length);
        outputStream.Write(encryptedIV, 0, encryptedIV.Length);
        tempStream.CopyTo(outputStream);
        outputStream.Write(signature, 0, signature.Length);
    }


    private (byte[] Key, byte[] IV) GenerateAesKeyAndIV()
    {
        using Aes aes = Aes.Create();
        aes.KeySize = AesKeySize;
        aes.GenerateKey();
        aes.GenerateIV();
        return (aes.Key, aes.IV);
    }

    private void EncryptStreamWithAes(Stream inputStream, Stream outputStream, byte[] aesKey, byte[] aesIV)
    {
        using Aes aes = Aes.Create();
        aes.KeySize = AesKeySize;
        aes.Key = aesKey;
        aes.IV = aesIV;

        using ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        using CryptoStream cryptoStream = new CryptoStream(outputStream, encryptor, CryptoStreamMode.Write, leaveOpen: true);

        inputStream.CopyTo(cryptoStream);
        cryptoStream.FlushFinalBlock();
    }

    private byte[] CreateSignatureForStream(Stream stream, RSA rsaPrivate)
    {
        using SHA256 sha256 = SHA256.Create();
        byte[] hash = sha256.ComputeHash(stream);
        return rsaPrivate.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    private void WriteOutputStream(Stream outputStream, byte[] encryptedKey, byte[] encryptedIV, Stream tempStream, byte[] signature)
    {
        outputStream.Write(encryptedKey, 0, encryptedKey.Length);
        outputStream.Write(encryptedIV, 0, encryptedIV.Length);

        // Verschlüsselte Daten kopieren
        tempStream.CopyTo(outputStream);

        outputStream.Write(signature, 0, signature.Length);
    }
}
