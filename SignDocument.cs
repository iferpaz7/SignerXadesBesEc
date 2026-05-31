using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace SignerXadesBesEc
{
    /// <summary>
    /// Clase responsable de realizar el proceso de firma XAdES-BES sobre un documento XML.
    /// Utiliza System.Security.Cryptography.Xml nativo de .NET para generar firmas XAdES-BES.
    /// Esta es la implementación genérica. Para SRI Ecuador use <see cref="SignDocumentSriEcuador"/>.
    /// </summary>
    public class SignDocument
    {
        private const string XadesNamespaceUri = "http://uri.etsi.org/01903/v1.3.2#";
        private const string XmlDsigNamespaceUri = "http://www.w3.org/2000/09/xmldsig#";
        private const string CanonicalizationMethod = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

        /// <summary>
        /// Firma un documento XML en formato XAdES-BES (enveloped) utilizando el certificado proporcionado.
        /// </summary>
        /// <param name="xmlUnsigned">XML original sin firmar.</param>
        /// <param name="password">Contraseña del certificado (archivo PKCS#12).</param>
        /// <param name="certificate">Bytes del archivo PKCS#12 que contiene certificado y clave privada.</param>
        /// <param name="xmlSigned">(ref) Resultado del XML firmado si el proceso finaliza correctamente.</param>
        /// <returns>true si la firma se generó correctamente; false en caso de error.</returns>
        public bool Sign(string xmlUnsigned, string password, byte[] certificate, ref string? xmlSigned)
        {
            try
            {
                // Load certificate. Note: EphemeralKeySet is intentionally omitted because
                // System.Security.Cryptography.Xml's ComputeSignature() requires the CNG key
                // to be accessible via the standard provider chain — ephemeral keys bypass this.
                // The cert (and its temporary key store entry) is disposed immediately after signing.
                var cert = X509CertificateLoader.LoadPkcs12(certificate, password,
                    X509KeyStorageFlags.Exportable);

                // 2. Validar que el certificado tenga clave privada RSA
                if (!cert.HasPrivateKey)
                {
                    Console.WriteLine("Error: El certificado no contiene clave privada.");
                    xmlSigned = null;
                    cert.Dispose();
                    return false;
                }

                if (cert.GetRSAPrivateKey() == null)
                {
                    Console.WriteLine("Error: El certificado no usa RSA. Esta implementación requiere certificados RSA.");
                    xmlSigned = null;
                    cert.Dispose();
                    return false;
                }

                // 3. Cargar el XML a firmar
                var xmlDoc = new XmlDocument();
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.LoadXml(xmlUnsigned);

                // 4. Crear la firma XML
                var signedXml = new SignedXml(xmlDoc);
                signedXml.SigningKey = cert.GetRSAPrivateKey() ?? throw new InvalidOperationException("No se pudo obtener la clave privada RSA");

                // 5. Configurar SignedInfo con algoritmos correctos (RSA-SHA256, C14N)
                if (signedXml.SignedInfo != null)
                {
                    signedXml.SignedInfo.CanonicalizationMethod = CanonicalizationMethod;
                    signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;
                }

                // 6. Configurar la referencia al documento (firma enveloped)
                var reference = new Reference("");
                reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
                reference.AddTransform(new XmlDsigC14NTransform()); // C14N explícito
                reference.DigestMethod = SignedXml.XmlDsigSHA256Url;
                signedXml.AddReference(reference);

                // 7. Agregar información del certificado (KeyInfo)
                var keyInfo = new KeyInfo();
                keyInfo.AddClause(new KeyInfoX509Data(cert));
                signedXml.KeyInfo = keyInfo;

                // 8. Agregar propiedades XAdES-BES
                AddXadesInfo(signedXml, cert);

                // 9. Calcular la firma
                signedXml.ComputeSignature();

                // 10. Obtener el elemento XML de la firma
                var xmlDigitalSignature = signedXml.GetXml();

                // 11. Insertar la firma en el documento (como último hijo del elemento raíz)
                xmlDoc.DocumentElement?.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));

                // 12. Convertir a string
                using (var stringWriter = new StringWriter())
                using (var xmlWriter = XmlWriter.Create(stringWriter, new XmlWriterSettings
                {
                    Indent = false,
                    Encoding = System.Text.Encoding.UTF8,
                    OmitXmlDeclaration = false
                }))
                {
                    xmlDoc.Save(xmlWriter);
                    xmlSigned = stringWriter.ToString();
                }

                cert.Dispose();
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error al firmar el comprobante: {ex.Message}");
                Console.WriteLine($"Detalle: {ex.StackTrace}");
                xmlSigned = null;
                return false;
            }
        }

        /// <summary>
        /// Agrega las propiedades XAdES-BES al objeto SignedXml
        /// </summary>
        private void AddXadesInfo(SignedXml signedXml, X509Certificate2 cert)
        {
            var doc = new XmlDocument();

            // SignedProperties
            var signedPropertiesId = "SignedProperties-" + Guid.NewGuid().ToString();
            var signedProperties = doc.CreateElement("xades", "SignedProperties", XadesNamespaceUri);
            signedProperties.SetAttribute("Id", signedPropertiesId);

            // SignedSignatureProperties
            var signedSignatureProperties = doc.CreateElement("xades", "SignedSignatureProperties", XadesNamespaceUri);

            // SigningTime
            var signingTime = doc.CreateElement("xades", "SigningTime", XadesNamespaceUri);
            signingTime.InnerText = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            signedSignatureProperties.AppendChild(signingTime);

            // SigningCertificate
            var signingCertificate = doc.CreateElement("xades", "SigningCertificate", XadesNamespaceUri);
            var certElement = doc.CreateElement("xades", "Cert", XadesNamespaceUri);

            // CertDigest
            var certDigest = doc.CreateElement("xades", "CertDigest", XadesNamespaceUri);
            var digestMethod = doc.CreateElement("ds", "DigestMethod", XmlDsigNamespaceUri);
            digestMethod.SetAttribute("Algorithm", SignedXml.XmlDsigSHA256Url);
            var digestValue = doc.CreateElement("ds", "DigestValue", XmlDsigNamespaceUri);

            using (var sha256 = SHA256.Create())
            {
                var hash = sha256.ComputeHash(cert.RawData);
                digestValue.InnerText = Convert.ToBase64String(hash);
            }

            certDigest.AppendChild(digestMethod);
            certDigest.AppendChild(digestValue);
            certElement.AppendChild(certDigest);

            // IssuerSerial
            var issuerSerial = doc.CreateElement("xades", "IssuerSerial", XadesNamespaceUri);
            var x509IssuerName = doc.CreateElement("ds", "X509IssuerName", XmlDsigNamespaceUri);
            x509IssuerName.InnerText = cert.IssuerName.Name;
            var x509SerialNumber = doc.CreateElement("ds", "X509SerialNumber", XmlDsigNamespaceUri);
            x509SerialNumber.InnerText = cert.SerialNumber;
            issuerSerial.AppendChild(x509IssuerName);
            issuerSerial.AppendChild(x509SerialNumber);
            certElement.AppendChild(issuerSerial);

            signingCertificate.AppendChild(certElement);
            signedSignatureProperties.AppendChild(signingCertificate);

            signedProperties.AppendChild(signedSignatureProperties);

            // QualifyingProperties
            var qualifyingProperties = doc.CreateElement("xades", "QualifyingProperties", XadesNamespaceUri);
            qualifyingProperties.SetAttribute("Target", "#Signature-" + Guid.NewGuid().ToString());
            qualifyingProperties.AppendChild(signedProperties);

            // Crear DataObject para contener las propiedades XAdES
            var dataObject = new DataObject();
            dataObject.Data = qualifyingProperties.SelectNodes(".") ?? throw new InvalidOperationException("Error al crear nodos XAdES");
            dataObject.Id = "XadesObject-" + Guid.NewGuid().ToString();

            signedXml.AddObject(dataObject);

            // Agregar referencia a SignedProperties
            var reference = new Reference("#" + signedPropertiesId);
            reference.Type = "http://uri.etsi.org/01903#SignedProperties";
            reference.DigestMethod = SignedXml.XmlDsigSHA256Url;
            signedXml.AddReference(reference);
        }
    }
}
