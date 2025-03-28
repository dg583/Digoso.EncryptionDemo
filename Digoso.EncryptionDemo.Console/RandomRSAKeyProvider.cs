using System.Security.Cryptography;

public class RandomRSAKeyProvider : IRSAKeyProvider
{
    private readonly RSA _rsa;

    private RandomRSAKeyProvider(RSA rsa)
    {
        _rsa = rsa;
    }

    public static RandomRSAKeyProvider Create(int keySize)
    {
        return new RandomRSAKeyProvider(RSA.Create(keySize));
    }

    public static RandomRSAKeyProvider CreateFromPrivateKey(string privateKeyBase64)
    {
        RSA rsa = RSA.Create();
        rsa.ImportRSAPrivateKey(Convert.FromBase64String(privateKeyBase64), out _);

        return new RandomRSAKeyProvider(rsa);
    }

    public RSA GetRSAPublicKey() => _rsa;
    public RSA GetRSAPrivateKey() => _rsa;
}
