using System.Security.Cryptography;

public interface IRSAKeyProvider
{
    RSA GetRSAPublicKey();
    RSA GetRSAPrivateKey();
}