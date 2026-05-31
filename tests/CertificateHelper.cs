using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SignerXadesBesEc.Tests
{
    /// <summary>
    /// Genera certificados RSA auto-firmados en memoria para los tests.
    /// No se necesita un .p12 real — solo para tests funcionales de la firma.
    /// Los tests de integración contra SRI requieren un certificado real.
    /// </summary>
    internal static class CertificateHelper
    {
        private const string TestCertPassword = "TestPass123!";

        /// <summary>
        /// Crea un certificado RSA auto-firmado de 2048 bits válido por 1 año.
        /// Devuelve los bytes del PKCS#12 y la contraseña.
        /// </summary>
        public static (byte[] p12Bytes, string password) CreateSelfSignedRsaCert()
        {
            using var rsa = RSA.Create(2048);

            var req = new CertificateRequest(
                "CN=TestSigner, O=TestOrg, C=EC",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            // Basic constraints: end-entity, not a CA
            req.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(false, false, 0, true));

            // Key usage: digitalSignature + nonRepudiation
            req.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation,
                    true));

            var cert = req.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddMinutes(-1),
                DateTimeOffset.UtcNow.AddYears(1));

            var p12 = cert.Export(X509ContentType.Pfx, TestCertPassword);
            return (p12, TestCertPassword);
        }

        /// <summary>
        /// Crea un certificado ECDSA auto-firmado (para verificar que el código lo rechaza).
        /// </summary>
        public static (byte[] p12Bytes, string password) CreateSelfSignedEcdsaCert()
        {
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var req = new CertificateRequest(
                "CN=TestEcdsa, C=EC",
                ecdsa,
                HashAlgorithmName.SHA256);

            var cert = req.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddMinutes(-1),
                DateTimeOffset.UtcNow.AddYears(1));

            var p12 = cert.Export(X509ContentType.Pfx, TestCertPassword);
            return (p12, TestCertPassword);
        }

        /// <summary>
        /// Crea un certificado RSA expirado (para verificar validación de expiración).
        /// </summary>
        public static (byte[] p12Bytes, string password) CreateExpiredRsaCert()
        {
            using var rsa = RSA.Create(2048);

            var req = new CertificateRequest(
                "CN=ExpiredSigner, C=EC",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            var cert = req.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddYears(-2),
                DateTimeOffset.UtcNow.AddYears(-1));  // expired a year ago

            var p12 = cert.Export(X509ContentType.Pfx, TestCertPassword);
            return (p12, TestCertPassword);
        }

        public const string ValidClaveAcceso = "0101202401099999999900110010010000000011234567814";

        public static string SampleInvoiceXml =>
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<factura id=\"comprobante\" version=\"1.1.0\">" +
            "<infoTributaria><ambiente>1</ambiente><tipoEmision>1</tipoEmision>" +
            "<razonSocial>EMPRESA DEMO S.A.</razonSocial><ruc>9999999999001</ruc>" +
            $"<claveAcceso>{ValidClaveAcceso}</claveAcceso>" +
            "<codDoc>01</codDoc><estab>001</estab><ptoEmi>001</ptoEmi>" +
            "<secuencial>000000001</secuencial></infoTributaria>" +
            "<infoFactura><fechaEmision>01/01/2024</fechaEmision>" +
            "<totalSinImpuestos>100.00</totalSinImpuestos>" +
            "<importeTotal>112.00</importeTotal></infoFactura>" +
            "</factura>";
    }
}
