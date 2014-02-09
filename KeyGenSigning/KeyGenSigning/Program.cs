using CertLib;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace KeyGenSigning
{
    class Program
    {
        static void Main(string[] args)
        {
            var CA = CreateCertificateAuthority();

            Console.WriteLine("CA: " + CA);

            var subordinate = CreateSubordinate();

            Console.WriteLine("Subordinate: " + subordinate);

            var signedSubordinate = SignIt(subordinate, CA);

            Console.WriteLine("Signed: " + signedSubordinate);

            Console.Write("Press enter to close...");

            Console.ReadLine();
        }

        private static X509Certificate2 SignIt(X509Certificate2 subordinate, X509Certificate2 CA)
        {
            var csr = new CertificateSigningRequest()
            {
                KeySpecification = CertificateSigner.AT_SIGNATURE,
                Certificate = subordinate, 
                ExpirationLength = subordinate.NotAfter - subordinate.NotBefore
            };

            return CertificateSigner.SignCertificate(csr, CA);
        }

        private static X509Certificate2 CreateCertificateAuthority()
        {
            CspParameters parameters = new CspParameters()
            {
                ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider",
                ProviderType = 24,
                KeyContainerName = Guid.NewGuid().ToString(),
                KeyNumber = (int)KeyNumber.Signature,
                Flags = CspProviderFlags.UseMachineKeyStore
            };

            var extensions = new X509ExtensionCollection();

            extensions.Add(new X509BasicConstraintsExtension(true, false, 0, false));
            extensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.CrlSign |
                X509KeyUsageFlags.DataEncipherment |
                X509KeyUsageFlags.DigitalSignature |
                X509KeyUsageFlags.KeyAgreement |
                X509KeyUsageFlags.KeyCertSign |
                X509KeyUsageFlags.KeyEncipherment |
                X509KeyUsageFlags.NonRepudiation, false));

            var cgr = new CertificateGenerationRequest()
            {
                Subject = "Syfuhs Industries Certificate Authority",
                Parameters = parameters,
                SignatureAlgorithm = "1.2.840.113549.1.1.11",
                ExpirationLength = TimeSpan.FromDays(365 * 20),
                KeySize = 2048,
                Extensions = extensions
            };

            var cert = CertificateGenerator.CreateSelfSignedCertificate(cgr);
            return cert;
        }

        private static System.Security.Cryptography.X509Certificates.X509Certificate2 CreateSubordinate()
        {
            var oids = new OidCollection();
            oids.Add(new Oid("1.3.6.1.5.5.7.3.2")); // client auth
            oids.Add(new Oid("1.3.6.1.4.1.311.20.2.2")); // smart card login

            var extensions = new X509ExtensionCollection();
            extensions.Add(new X509EnhancedKeyUsageExtension(oids, true));

            var cgr = new CertificateGenerationRequest()
            {
                Subject = "steve@syfuhs.net",
                Extensions = extensions,
                ExpirationLength = TimeSpan.FromDays(365 * 5), 
                KeySize = 2048
            };

            var cert = CertificateGenerator.CreateSelfSignedCertificate(cgr);
            return cert;
        }
    }
}
