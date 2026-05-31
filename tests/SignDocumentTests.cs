using System;
using System.Xml;
using Xunit;
using SignerXadesBesEc;

namespace SignerXadesBesEc.Tests
{
    /// <summary>
    /// Tests para SignDocument (firma XAdES-BES genérica).
    /// Todos usan certificado RSA auto-firmado — no se necesita .p12 real.
    /// </summary>
    public class SignDocumentTests
    {
        private readonly byte[] _p12;
        private readonly string _pwd;

        public SignDocumentTests()
        {
            (_p12, _pwd) = CertificateHelper.CreateSelfSignedRsaCert();
        }

        // ── Happy path ────────────────────────────────────────────────────────────

        [Fact]
        public void Sign_ValidXml_ReturnsTrue()
        {
            var signer = new SignDocument();
            string? signed = null;

            var result = signer.Sign(CertificateHelper.SampleInvoiceXml, _pwd, _p12, ref signed);

            Assert.True(result);
            Assert.NotNull(signed);
            Assert.NotEmpty(signed!);
        }

        [Fact]
        public void Sign_ProducesWellFormedXml()
        {
            var signer = new SignDocument();
            string? signed = null;
            signer.Sign(CertificateHelper.SampleInvoiceXml, _pwd, _p12, ref signed);

            var doc = new XmlDocument();
            doc.LoadXml(signed!);
            Assert.NotNull(doc.DocumentElement);
        }

        [Fact]
        public void Sign_ContainsSignatureElement()
        {
            var signer = new SignDocument();
            string? signed = null;
            signer.Sign(CertificateHelper.SampleInvoiceXml, _pwd, _p12, ref signed);

            var doc = new XmlDocument();
            doc.LoadXml(signed!);
            var nsMgr = new XmlNamespaceManager(doc.NameTable);
            nsMgr.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");

            var sigNode = doc.SelectSingleNode("//ds:Signature", nsMgr);
            Assert.NotNull(sigNode);
        }

        [Fact]
        public void Sign_ContainsXadesSignedProperties()
        {
            var signer = new SignDocument();
            string? signed = null;
            signer.Sign(CertificateHelper.SampleInvoiceXml, _pwd, _p12, ref signed);

            Assert.Contains("SignedProperties", signed!);
            Assert.Contains("SigningTime", signed!);
            Assert.Contains("SigningCertificate", signed!);
        }

        [Fact]
        public void Sign_UsesRsaSha256Algorithm()
        {
            var signer = new SignDocument();
            string? signed = null;
            signer.Sign(CertificateHelper.SampleInvoiceXml, _pwd, _p12, ref signed);

            Assert.Contains("rsa-sha256", signed!);
        }

        [Fact]
        public void Sign_SignatureIsLastChildOfRoot()
        {
            var signer = new SignDocument();
            string? signed = null;
            signer.Sign(CertificateHelper.SampleInvoiceXml, _pwd, _p12, ref signed);

            var doc = new XmlDocument();
            doc.LoadXml(signed!);

            var lastChild = doc.DocumentElement!.LastChild;
            Assert.Equal("Signature", lastChild!.LocalName);
        }

        // ── Error cases ───────────────────────────────────────────────────────────

        [Fact]
        public void Sign_WrongPassword_ReturnsFalse()
        {
            var signer = new SignDocument();
            string? signed = null;

            var result = signer.Sign(CertificateHelper.SampleInvoiceXml, "wrong_password", _p12, ref signed);

            Assert.False(result);
            Assert.Null(signed);
        }

        [Fact]
        public void Sign_EcdsaCert_ReturnsFalse()
        {
            var (ecP12, ecPwd) = CertificateHelper.CreateSelfSignedEcdsaCert();
            var signer = new SignDocument();
            string? signed = null;

            var result = signer.Sign(CertificateHelper.SampleInvoiceXml, ecPwd, ecP12, ref signed);

            Assert.False(result);
            Assert.Null(signed);
        }

        [Fact]
        public void Sign_MalformedXml_ReturnsFalse()
        {
            var signer = new SignDocument();
            string? signed = null;

            var result = signer.Sign("<unclosed>", _pwd, _p12, ref signed);

            Assert.False(result);
            Assert.Null(signed);
        }
    }
}
