using API.Dto;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ess;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace API.Signature
{
    public class SignatureService
    {
        private string Password { get; set; } = string.Empty;
        private string DllLibPath { get; set; } = "eps2003csp11.dll";
        private string TokenCertificate { get; set; } = string.Empty;
        public string SignInvoice(SignRequestDto data)
        {
            if (string.IsNullOrEmpty(data.Document))
            {
                return "{\"status\":0,\"message\":\"[Document] attribute can't be null or empty!\"}";
            }

            if (string.IsNullOrEmpty(data.TokenCertificate))
            {
                return "{\"status\":0,\"message\":\"[TokenCertificate] attribute can't be null or empty!\"}";
            }

            if (string.IsNullOrEmpty(data.Password))
            {
                return "{\"status\":0,\"message\":\"[Password] attribute can't be null or empty!\"}";
            }

            TokenCertificate = data.TokenCertificate;
            Password = data.Password;

            string cades = SignWithCMS(data.Document);
            return cades;
        }

        private string SignWithCMS(string serializedJson)
        {
            byte[] data = Encoding.UTF8.GetBytes(serializedJson);

            Pkcs11InteropFactories factories = new Pkcs11InteropFactories();

            try
            {
                using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, DllLibPath, AppType.MultiThreaded))
                {
                    ISlot slot = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent).FirstOrDefault()!;

                    if (slot is null)
                    {
                        Console.WriteLine("NO_SOLTS_FOUND");
                        throw new Exception("NO_SOLTS_FOUND");
                    }

                    ITokenInfo tokenInfo = slot.GetTokenInfo();

                    ISlotInfo slotInfo = slot.GetSlotInfo();

                    using (var session = slot.OpenSession(SessionType.ReadWrite))
                    {
                        try
                        {
                            session.Login(CKU.CKU_USER, Encoding.UTF8.GetBytes(Password));
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("PASSWORD_INVAILD");
                            Console.WriteLine(e.GetBaseException().Message);
                            throw new Exception("PASSWORD_INVAILD");
                        }

                        var certificateSearchAttributes = new List<IObjectAttribute>()
                        {
                            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
                            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509)
                        };

                        IObjectHandle certificate = session.FindAllObjects(certificateSearchAttributes).FirstOrDefault()!;

                        if (certificate is null)
                        {
                            Console.WriteLine("CERTIFICATE_NOT_FOUND");
                            throw new Exception("CERTIFICATE_NOT_FOUND");
                        }

                        X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);

                        store.Open(OpenFlags.MaxAllowed);

                        // find cert by thumbprint
                        var foundCerts = store.Certificates.Find(X509FindType.FindByIssuerName, TokenCertificate, false);

                        //var foundCerts = store.Certificates.Find(X509FindType.FindBySerialNumber, "2b1cdda84ace68813284519b5fb540c2", true);

                        if (foundCerts.Count == 0)
                        {
                            Console.WriteLine("NO_DEVICE_DETECTED");
                            throw new Exception("NO_DEVICE_DETECTED");
                        }
                        var certForSigning = foundCerts[0];
                        store.Close();

                        ContentInfo content = new ContentInfo(new Oid("1.2.840.113549.1.7.5"), data);

                        SignedCms cms = new SignedCms(content, true);

                        EssCertIDv2 bouncyCertificate = new EssCertIDv2(new Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier(new DerObjectIdentifier("1.2.840.113549.1.9.16.2.47")), HashBytes(certForSigning.RawData));

                        SigningCertificateV2 signerCertificateV2 = new SigningCertificateV2(new EssCertIDv2[] { bouncyCertificate });

                        CmsSigner signer = new CmsSigner(certForSigning);

                        signer.DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1");

                        signer.SignedAttributes.Add(new Pkcs9SigningTime(DateTime.UtcNow));
                        signer.SignedAttributes.Add(new AsnEncodedData(new Oid("1.2.840.113549.1.9.16.2.47"), signerCertificateV2.GetEncoded()));

                        cms.ComputeSignature(signer);

                        var output = cms.Encode();

                        return Convert.ToBase64String(output);
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                throw;
            }
        }
        private byte[] HashBytes(byte[] input)
        {
            using (SHA256 sha = SHA256.Create())
            {
                return sha.ComputeHash(input);
            }
        }
    }
}
