# EncryptionDemo

This is a sample project demonstrating encryption and signing of data using **RSA** and **AES**. The project shows how to create an RSA key pair and use it to encrypt the AES key, which is then used to encrypt the data. It also demonstrates how to create a digital signature for the encrypted data.

## Features

- **Encryption**: Data is encrypted with **AES**, and the AES key is encrypted with **RSA**.
- **Signing**: The encrypted data is signed with a private **RSA key**.
- **Decryption**: The receiver can decrypt the AES key and IV (Initialization Vector) using the RSA private key, and then decrypt the encrypted data.

## Technologies Used

- **RSA**: Asymmetric encryption
- **AES**: Symmetric encryption
- **SHA256**: Hashing for digital signatures
- **C#**: Programming language
- **.NET**: Framework

## Project Structure

- **`EncryptionService`**: Provides methods for encrypting, signing, and decrypting data.
- **`RandomRSAKeyProvider`**: Generates RSA key pairs and provides both public and private RSA keys. It can import RSA keys from Base64-encoded strings or byte arrays.

## How it works

### 1. **Encryption**

The `EncryptionService` uses RSA to encrypt the **AES key** and **AES Initialization Vector (IV)**. The actual data is then encrypted with AES. The encrypted data, the encrypted AES key, and the IV are stored together with a digital signature of the encrypted data in a file.

### 2. **Decryption**

The receiver first decrypts the AES key and IV using the private RSA key. Then, the encrypted data is decrypted using AES.

### 3. **Signing**

The encrypted data is signed with the private RSA key to ensure the data is authentic and hasn’t been tampered with.

## Example Code

### `EncryptionService`

```csharp
using System.Security.Cryptography;

public class EncryptionService
{
    private const int AesKeySize = 256;
    private readonly IRSAKeyProvider _keyProvider;

    public EncryptionService(IRSAKeyProvider keyProvider)
    {
        _keyProvider = keyProvider;
    }

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
}
