using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

const string CertPath = "mycert.pfx"; // Zertifikatsdatei
const string CertPassword = "password"; // Passwort für das Zertifikat
const string DataFile = "measurement_data.txt";
const string EncryptedFile = "measurement_data.enc";

Console.WriteLine("Wählen Sie die Verschlüsselungsmethode:");
Console.WriteLine("1 - Verschlüsselung mit Zertifikat (.pfx)");
Console.WriteLine("2 - Verschlüsselung mit manuellem RSA-Key");
Console.Write("Eingabe: ");
string choice = Console.ReadLine();

if (choice == "1")
{
    EncryptWithCertificate();
}
else if (choice == "2")
{
    EncryptWithManualKey();
}
else
{
    Console.WriteLine("Ungültige Auswahl.");
}

/// <summary>
/// Verschlüsselt die Datei mit einem RSA-Zertifikat (.pfx)
/// </summary>
void EncryptWithCertificate()
{
    if (!File.Exists(CertPath))
    {
        Console.WriteLine("Zertifikat nicht gefunden!");
        return;
    }

    X509Certificate2 cert = new X509Certificate2(CertPath, CertPassword);
    RSA rsa = cert.GetRSAPublicKey();
    RSA rsaPrivate = cert.GetRSAPrivateKey();

    EncryptAndSignFile(DataFile, EncryptedFile, rsa, rsaPrivate);
    Console.WriteLine("Datei erfolgreich mit Zertifikat verschlüsselt.");
}

/// <summary>
/// Verschlüsselt die Datei mit einem manuell generierten RSA-Key
/// </summary>
void EncryptWithManualKey()
{
    using (RSA rsa = RSA.Create(4096)) // 4096-bit Schlüssel
    {
        EncryptAndSignFile(DataFile, EncryptedFile, rsa, rsa);
        Console.WriteLine("Datei erfolgreich mit manuellem Key verschlüsselt.");
    }
}

/// <summary>
/// Hybrid-Verschlüsselung: AES-256 + RSA + Signatur
/// </summary>
void EncryptAndSignFile(string inputFile, string outputFile, RSA rsaPublic, RSA rsaPrivate)
{
    byte[] fileBytes = File.ReadAllBytes(inputFile);
    byte[] aesKey, aesIV;
    byte[] encryptedData = EncryptWithAES(fileBytes, out aesKey, out aesIV);

    // Verschlüsseln des AES-Schlüssels mit RSA
    byte[] encryptedKey = rsaPublic.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA256);
    byte[] encryptedIV = rsaPublic.Encrypt(aesIV, RSAEncryptionPadding.OaepSHA256);

    // Datei signieren
    byte[] signature = SignData(encryptedData, rsaPrivate);

    // Datei speichern
    using (FileStream fs = new FileStream(outputFile, FileMode.Create))
    {
        fs.Write(encryptedKey, 0, encryptedKey.Length);
        fs.Write(encryptedIV, 0, encryptedIV.Length);
        fs.Write(encryptedData, 0, encryptedData.Length);
        fs.Write(signature, 0, signature.Length);
    }
}

byte[] EncryptWithAES(byte[] data, out byte[] key, out byte[] iv)
{
    using (Aes aes = Aes.Create())
    {
        aes.KeySize = 256;
        aes.GenerateKey();
        aes.GenerateIV();
        key = aes.Key;
        iv = aes.IV;

        using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
        using (MemoryStream ms = new MemoryStream())
        using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        {
            cs.Write(data, 0, data.Length);
            cs.FlushFinalBlock();
            return ms.ToArray();
        }
    }
}

byte[] SignData(byte[] data, RSA rsa)
{
    using (SHA256 sha256 = SHA256.Create())
    {
        byte[] hash = sha256.ComputeHash(data);
        return rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }
}
