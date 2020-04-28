using System;
using System.Security.Cryptography;
using System.Text;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Azure.Security.KeyVault.Secrets;

namespace EncryptionConsoleApp
{
    class Program
    {
        static void Main(string[] args)
        {
            var credential = new InteractiveBrowserCredential();

            var kvUri = "[key vault uri]";

            var client = new KeyClient(new Uri(kvUri), credential);
            var key = client.GetKey("[kek key name]");
            var cryptoClient = new CryptographyClient(key.Value.Id, credential);
            var secretClient = new SecretClient(new Uri(kvUri), credential);
            var encryptedDEK = secretClient.GetSecret("[dek key name]");
            DecryptResult decryptDek = cryptoClient.Decrypt(EncryptionAlgorithm.RsaOaep256, Convert.FromBase64String(encryptedDEK.Value.Value));
            var keynew = decryptDek.Plaintext[0..16];
            string doYouWanttoContinue = "Y";
            while (doYouWanttoContinue == "Y")
            {
                Console.WriteLine("Enter string to decrypt:");
                var stringtoEncrypt = Console.ReadLine();
                Console.WriteLine("Decrypting...");

                using (var aesGcm = new AesGcm(keynew))
                {
                    var encryptedBytes = Convert.FromBase64String(stringtoEncrypt);

                    //Here we will extract the nonce and tag from encrypted bytes
                    var nonceForDecryption = encryptedBytes[0..12];
                    var cipherTextForDecryption = encryptedBytes[12..^16];
                    var tagForDecryption = encryptedBytes[^16..^0];
                    var plainTextBytes = new byte[cipherTextForDecryption.Length];

                    aesGcm.Decrypt(nonceForDecryption, cipherTextForDecryption, tagForDecryption, plainTextBytes);
                    Console.WriteLine("Encrypted Message is : " + Encoding.UTF8.GetString(plainTextBytes));
                    Console.WriteLine("Decrypted Message: " + Encoding.UTF8.GetString(plainTextBytes));

                }

                Console.WriteLine("Do you want to Encrypt another message? Y/N");
                doYouWanttoContinue = Console.ReadLine();
            }
        }
    }
}
