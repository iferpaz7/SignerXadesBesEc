using System;
using System.Xml;
using Xunit;
using SignerXadesBesEc;

namespace SignerXadesBesEc.Tests
{
    /// <summary>
    /// Tests para SignDocumentSriEcuador — cumplimiento con Ficha Técnica SRI v2.32.
    /// Todos usan certificado RSA auto-firmado — no se necesita .p12 real.
    /// </summary>
    public class SignDocumentSriEcuadorTests
    {
        private readonly byte[] _p12;
        private readonly string _pwd;
        private const string ClaveAcceso = CertificateHelper.ValidClaveAcceso;

        public SignDocumentSriEcuadorTests()
        {
            (_p12, _pwd) = CertificateHelper.CreateSelfSignedRsaCert();
        }

        // ── Happy path ────────────────────────────────────────────────────────────

        [Fact]
        public void Sign_ValidXml_ReturnsTrue()
        {
            var signer = new SignDocumentSriEcuador();
            string? signed = null;

            var result = signer.Sign(CertificateHelper.SampleInvoiceXml, _pwd, _p12, ClaveAcceso, ref signed);

            Assert.True(result);
            Assert.NotNull(signed);
            Assert.NotEmpty(signed!);
        }

        [Fact]
        public void Sign_ProducesWellFormedXml()
        {
            var signer = new SignDocumentSriEcuador();
            string? signed = null;
            signer.Sign(CertificateHelper.SampleInvoiceXml, _pwd, _p12, ClaveAcceso, ref signed);

            var doc = new XmlDocument();
            doc.LoadXml(signed!);
            Assert.NotNull(doc.DocumentElement);
        }

        // ── SRI structure requirements ────────────────────────────────────────────

        [Fact]
        public void Sign_SignatureIsLastChildOfRoot()
        {
            var signer = new SignDocumentSriEcuador();
            string? signed = null;
            signer.Sign(CertificateHelper.SampleInvoiceXml, _pwd, _p12, ClaveAcceso, ref signed);

            var doc = new XmlDocument();
            doc.LoadXml(signed!);

            var lastChild = doc.DocumentElement!.LastChild;
            Assert.Equal("Signature", lastChild!.LocalName);
        }

        [Fact]
        public void Sign_ContainsRandomNumericIds()
        {
            // New format (MITyC legacy): random numeric IDs, NOT clave-de-acceso based
            var signer = new SignDocumentSriEcuador();
            string? signed = null;
            signer.Sign(CertificateHelper.SampleInvoiceXml, _pwd, _p12, ClaveAcceso, ref signed);

            Assert.Contains("SignedPropertiesID", signed!);
            Assert.Contains("Reference-ID-", signed!);
            Assert.Contains("SignatureValue", signed!);
            Assert.Contains("Certificate", signed!);
            // Must NOT contain clave-acceso in IDs (legacy format)
            Assert.DoesNotContain($"Signature{ClaveAcceso}\"", signed!);
        }

        [Fact]
        public void Sign_ContainsSignedDataObjectProperties()
        {
            var signer = new SignDocumentSriEcuador();
            string? signed = null;
            signer.Sign(CertificateHelper.SampleInvoiceXml, _pwd, _p12, ClaveAcceso, ref signed);

            Assert.Contains("SignedDataObjectProperties", signed!);
            Assert.Contains("DataObjectFormat", signed!);
            Assert.Contains("text/xml", signed!);
            Assert.Contains("contenido comprobante", signed!);
        }

        [Fact]
        public void Sign_ContainsRsaKeyValue()
        {
            var signer = new SignDocumentSriEcuador();
            string? signed = null;
            signer.Sign(CertificateHelper.SampleInvoiceXml, _pwd, _p12, ClaveAcceso, ref signed);

            Assert.Contains("RSAKeyValue", signed!);
            Assert.Contains("Modulus", signed!);
            Assert.Contains("Exponent", signed!);
        }

        [Fact]
        public void Sign_ContainsCanonicalizationMethod()
        {
            var signer = new SignDocumentSriEcuador();
            string? signed = null;
            signer.Sign(CertificateHelper.SampleInvoiceXml, _pwd, _p12, ClaveAcceso, ref signed);

            Assert.Contains("REC-xml-c14n-20010315", signed!);
        }

        [Fact]
        public void Sign_ContainsEnvelopedAndC14NTransforms()
        {
            var signer = new SignDocumentSriEcuador();
            string? signed = null;
            signer.Sign(CertificateHelper.SampleInvoiceXml, _pwd, _p12, ClaveAcceso, ref signed);

            Assert.Contains("enveloped-signature", signed!);
            Assert.Contains("REC-xml-c14n-20010315", signed!);
        }

        [Fact]
        public void Sign_SigningTimeContainsEcuadorOffset()
        {
            var signer = new SignDocumentSriEcuador();
            string? signed = null;
            signer.Sign(CertificateHelper.SampleInvoiceXml, _pwd, _p12, ClaveAcceso, ref signed);

            Assert.Contains("-05:00", signed!);
        }

        [Fact]
        public void Sign_SignedPropertiesReferenceBeforeContentReference()
        {
            var signer = new SignDocumentSriEcuador();
            string? signed = null;
            signer.Sign(CertificateHelper.SampleInvoiceXml, _pwd, _p12, ClaveAcceso, ref signed);

            var idxSignedProps = signed!.IndexOf("SignedPropertiesID", StringComparison.Ordinal);
            var idxContentRef  = signed!.IndexOf("Reference-ID-", StringComparison.Ordinal);

            Assert.True(idxSignedProps >= 0, "SignedPropertiesID not found in output");
            Assert.True(idxContentRef >= 0, "Reference-ID not found in output");
            Assert.True(idxSignedProps < idxContentRef,
                "SRI requiere que la referencia a SignedProperties aparezca ANTES que la referencia al contenido");
        }

        [Fact]
        public void Sign_UsesXadesNamespace()
        {
            var signer = new SignDocumentSriEcuador();
            string? signed = null;
            signer.Sign(CertificateHelper.SampleInvoiceXml, _pwd, _p12, ClaveAcceso, ref signed);

            Assert.Contains("http://uri.etsi.org/01903/v1.3.2#", signed!);
        }

        // ── Error / validation cases ───────────────────────────────────────────────

        [Fact]
        public void Sign_ClaveAccesoTooShort_ReturnsFalse()
        {
            var signer = new SignDocumentSriEcuador();
            string? signed = null;

            var result = signer.Sign(CertificateHelper.SampleInvoiceXml, _pwd, _p12, "1234", ref signed);

            Assert.False(result);
            Assert.Null(signed);
        }

        [Fact]
        public void Sign_ClaveAccesoEmpty_ReturnsFalse()
        {
            var signer = new SignDocumentSriEcuador();
            string? signed = null;

            var result = signer.Sign(CertificateHelper.SampleInvoiceXml, _pwd, _p12, "", ref signed);

            Assert.False(result);
            Assert.Null(signed);
        }

        [Fact]
        public void Sign_WrongPassword_ReturnsFalse()
        {
            var signer = new SignDocumentSriEcuador();
            string? signed = null;

            var result = signer.Sign(CertificateHelper.SampleInvoiceXml, "wrong_pass", _p12, ClaveAcceso, ref signed);

            Assert.False(result);
            Assert.Null(signed);
        }

        [Fact]
        public void Sign_EcdsaCert_ReturnsFalse()
        {
            var (ecP12, ecPwd) = CertificateHelper.CreateSelfSignedEcdsaCert();
            var signer = new SignDocumentSriEcuador();
            string? signed = null;

            var result = signer.Sign(CertificateHelper.SampleInvoiceXml, ecPwd, ecP12, ClaveAcceso, ref signed);

            Assert.False(result);
            Assert.Null(signed);
        }

        [Fact]
        public void Sign_MalformedXml_ReturnsFalse()
        {
            var signer = new SignDocumentSriEcuador();
            string? signed = null;

            var result = signer.Sign("<unclosed>", _pwd, _p12, ClaveAcceso, ref signed);

            Assert.False(result);
            Assert.Null(signed);
        }

        [Fact]
        public void Sign_EmptyXml_ReturnsFalse()
        {
            var signer = new SignDocumentSriEcuador();
            string? signed = null;

            var result = signer.Sign("", _pwd, _p12, ClaveAcceso, ref signed);

            Assert.False(result);
            Assert.Null(signed);
        }

        // ── Idempotency ───────────────────────────────────────────────────────────

        [Fact]
        public void Sign_TwoCallsProduceDifferentSigningTimes()
        {
            var signer = new SignDocumentSriEcuador();
            string? signed1 = null, signed2 = null;

            // Use separate cert instances for each call
            var (p12a, pwda) = CertificateHelper.CreateSelfSignedRsaCert();
            var (p12b, pwdb) = CertificateHelper.CreateSelfSignedRsaCert();

            signer.Sign(CertificateHelper.SampleInvoiceXml, pwda, p12a, ClaveAcceso, ref signed1);
            System.Threading.Thread.Sleep(1100);
            signer.Sign(CertificateHelper.SampleInvoiceXml, pwdb, p12b, ClaveAcceso, ref signed2);

            Assert.NotNull(signed1);
            Assert.NotNull(signed2);

            var doc1 = new XmlDocument();
            var doc2 = new XmlDocument();
            doc1.LoadXml(signed1!);
            doc2.LoadXml(signed2!);

            var nsMgr = new XmlNamespaceManager(doc1.NameTable);
            nsMgr.AddNamespace("etsi", "http://uri.etsi.org/01903/v1.3.2#");
            var t1 = doc1.SelectSingleNode("//etsi:SigningTime", nsMgr)?.InnerText;
            var t2 = doc2.SelectSingleNode("//etsi:SigningTime", nsMgr)?.InnerText;

            Assert.NotEqual(t1, t2);
        }
    }
}
