using System.IO;
using System.Security.Cryptography;
using Digoso.EncryptionDemo;
using Xunit;

namespace Digoso.Encryption.Tests
{
    public class EncryptionDecryptionTests
    {
        private readonly EncryptionService _encryptionService;
        private readonly DecryptionService _decryptionService;

        public EncryptionDecryptionTests()
        {
            var keyProvider = new InMemoryRSAKeyProvider();
            _encryptionService = new EncryptionService(keyProvider);
            _decryptionService = new DecryptionService(keyProvider);
        }

        [Fact]
        public void EncryptAndDecrypt_ShouldReturnOriginalData()
        {
            // Arrange
            string originalData = "This is a test string.";
            byte[] originalBytes = System.Text.Encoding.UTF8.GetBytes(originalData);

            using var inputStream = new MemoryStream(originalBytes);
            using var encryptedStream = new MemoryStream();
            using var decryptedStream = new MemoryStream();

            // Act
            _encryptionService.Encrypt(inputStream, encryptedStream);
            encryptedStream.Seek(0, SeekOrigin.Begin);
            _decryptionService.Decrypt(encryptedStream, decryptedStream);

            // Assert
            byte[] decryptedBytes = decryptedStream.ToArray();
            string decryptedData = System.Text.Encoding.UTF8.GetString(decryptedBytes);
            Assert.Equal(originalData, decryptedData);
        }
    }

    public class InMemoryRSAKeyProvider : IRSAKeyProvider
    {
        private readonly RSA _rsa;

        public InMemoryRSAKeyProvider()
        {
            _rsa = RSA.Create(4096);
        }

        public RSA GetRSAPublicKey()
        {
            return _rsa;
        }

        public RSA GetRSAPrivateKey()
        {
            return _rsa;
        }
    }
}
