using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

public class X509CertificateKeyProvider : IRSAKeyProvider
{
    /// <summary>
    /// The path to the certificate file.
    /// </summary>
    private readonly string _path;

    /// <remarks>
    /// The password is stored in a SecureString to avoid storing it in memory as plain text.
    /// </remarks>
    private readonly SecureString _password;

    private X509CertificateKeyProvider(string path, SecureString password)
    {
        _path = path;
        _password = password;
    }

    /// <summary>
    /// Creates a new instance of the <see cref="X509CertificateKeyProvider"/> class.
    /// </summary>
    /// <exception cref="FileNotFoundException">Thrown if the cert file does not exists</exception>
    public static X509CertificateKeyProvider Create(string path, string password)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException("Certificate file not found.", path);

        SecureString secureString = new SecureString();
        foreach (char c in password)
        {
            secureString.AppendChar(c);
        }

        secureString.MakeReadOnly();

        return new X509CertificateKeyProvider(path, secureString);
    }

    private X509Certificate2 GetCertificate()
    {
        var passwordPtr = Marshal.SecureStringToGlobalAllocUnicode(_password);
        return new X509Certificate2(_path, Marshal.PtrToStringUni(passwordPtr));
    }

    public RSA GetRSAPublicKey() => GetCertificate().GetRSAPublicKey();
    public RSA GetRSAPrivateKey() => GetCertificate().GetRSAPrivateKey();
}