using System;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml; // XmlDsigC14NTransform — cross-platform via NuGet
using System.Text;
using System.Xml;

namespace SignerXadesBesEc
{
    /// <summary>
    /// Firma XAdES-BES para SRI Ecuador replicando fielmente la salida de MITyCLibXADES:
    ///  - RSA-SHA1 (xmldsig#rsa-sha1), digests SHA-1
    ///  - 3 referencias: SignedProperties | KeyInfo | comprobante
    ///  - IDs numéricos aleatorios cortos
    ///  - SignedInfo/KeyInfo/Object construidos manualmente para controlar IDs exactos
    ///  - SignatureValue calculado con RSA PKCS#1 v1.5 + SHA-1
    /// </summary>
    public class SignDocumentSriEcuador
    {
        private const string DsNs   = "http://www.w3.org/2000/09/xmldsig#";
        private const string EtsiNs = "http://uri.etsi.org/01903/v1.3.2#";
        private const string C14N   = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
        private const string RsaSha1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
        private const string Sha1Uri = "http://www.w3.org/2000/09/xmldsig#sha1";

        public bool Sign(string xmlUnsigned, string password, byte[] certificate,
                         string claveAcceso, ref string? xmlSigned)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(claveAcceso) || claveAcceso.Length != 49)
                { Console.WriteLine("Error: La clave de acceso debe tener 49 dígitos."); return false; }

                // EphemeralKeySet: do not persist key material to disk — required on Linux/macOS
                var cert = X509CertificateLoader.LoadPkcs12(certificate, password,
                    X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
                if (!cert.HasPrivateKey || cert.GetRSAPrivateKey() == null)
                {
                    Console.WriteLine("Error: Certificado sin clave privada RSA.");
                    cert.Dispose(); xmlSigned = null; return false;
                }

                // ── IDs numéricos aleatorios ──────────────────────────────────────
                var rng = new Random();
                string sigId    = $"Signature{rng.Next(10000,99999)}";
                string siId     = $"Signature-SignedInfo{rng.Next(10000,99999)}";
                string spId     = $"{sigId}-SignedProperties{rng.Next(100000,999999)}";
                string certId   = $"Certificate{rng.Next(1000000,9999999)}";
                string refId    = $"Reference-ID-{rng.Next(100000,999999)}";
                string objId    = $"{sigId}-Object{rng.Next(100000,999999)}";
                string svId     = $"SignatureValue{rng.Next(100000,999999)}";
                string spRefId  = $"SignedPropertiesID{rng.Next(10000,99999)}";

                // ── Cargar y preparar XML ─────────────────────────────────────────
                var xmlDoc = new XmlDocument { PreserveWhitespace = true };
                xmlDoc.LoadXml(xmlUnsigned);
                if (xmlDoc.DocumentElement == null)
                { Console.WriteLine("Error: XML sin elemento raíz."); cert.Dispose(); xmlSigned = null; return false; }
                xmlDoc.DocumentElement.SetAttribute("id", "comprobante");

                // ── Construir ds:Signature completo en documento auxiliar ─────────
                var sigDoc = new XmlDocument();
                var sigEl = sigDoc.CreateElement("ds", "Signature", DsNs);
                sigEl.SetAttribute("xmlns:ds", DsNs);
                sigEl.SetAttribute("xmlns:etsi", EtsiNs);
                sigEl.SetAttribute("Id", sigId);
                sigDoc.AppendChild(sigEl);

                // ── ds:KeyInfo (construido ANTES para poder calcular su digest) ───
                var kiEl = BuildKeyInfo(sigDoc, cert, certId);
                sigEl.AppendChild(kiEl);

                // ── etsi:QualifyingProperties / SignedProperties ──────────────────
                var objEl = sigDoc.CreateElement("ds", "Object", DsNs);
                objEl.SetAttribute("Id", objId);
                var qpEl  = sigDoc.CreateElement("etsi", "QualifyingProperties", EtsiNs);
                qpEl.SetAttribute("Target", $"#{sigId}");
                var spEl  = BuildSignedProperties(sigDoc, cert, sigId, spId, certId, refId);
                qpEl.AppendChild(spEl);
                objEl.AppendChild(qpEl);
                // (Object appended to sigEl later — append now so ImportNode finds IDs)
                sigEl.AppendChild(objEl);

                // ── Import sigDoc's tree into xmlDoc so C14N sees the right context ─
                // We canonicalize sub-elements using a helper that operates on detached docs.

                // ── Digest de SignedProperties ────────────────────────────────────
                byte[] spDigest = Sha1C14NDigest(spEl);

                // ── Digest de KeyInfo ─────────────────────────────────────────────
                byte[] kiDigest = Sha1C14NDigest(kiEl);

                // ── Digest de comprobante (enveloped = C14N del XML original sin firma) ─
                // XML original ya tiene id="comprobante"; no hay firma todavía → C14N completo
                byte[] compDigest = Sha1C14NDigestDoc(xmlDoc);

                // ── ds:SignedInfo ─────────────────────────────────────────────────
                var siEl = sigDoc.CreateElement("ds", "SignedInfo", DsNs);
                siEl.SetAttribute("Id", siId);
                siEl.AppendChild(Elem(sigDoc, "ds", "CanonicalizationMethod", DsNs, "Algorithm", C14N));
                siEl.AppendChild(Elem(sigDoc, "ds", "SignatureMethod", DsNs, "Algorithm", RsaSha1));

                // Ref 1: SignedProperties
                siEl.AppendChild(BuildReference(sigDoc, spRefId, $"#{spId}",
                    "http://uri.etsi.org/01903#SignedProperties", spDigest));
                // Ref 2: KeyInfo
                siEl.AppendChild(BuildReference(sigDoc, null, $"#{certId}", null, kiDigest));
                // Ref 3: comprobante
                var r3 = BuildReference(sigDoc, refId, "#comprobante", null, compDigest);
                var tforms = sigDoc.CreateElement("ds", "Transforms", DsNs);
                tforms.AppendChild(Elem(sigDoc, "ds", "Transform", DsNs, "Algorithm",
                    "http://www.w3.org/2000/09/xmldsig#enveloped-signature"));
                r3.InsertBefore(tforms, r3.FirstChild);
                siEl.AppendChild(r3);

                // Insert SignedInfo as first child of Signature (before KeyInfo)
                sigEl.InsertBefore(siEl, kiEl);

                // ── Calcular SignatureValue (RSA-SHA1 sobre C14N de SignedInfo) ───
                byte[] siBytes = C14NBytes(siEl);
                byte[] sigBytes;
                using (var rsa = cert.GetRSAPrivateKey()!)
                    sigBytes = rsa.SignData(siBytes, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);

                // ── ds:SignatureValue ─────────────────────────────────────────────
                var svEl = sigDoc.CreateElement("ds", "SignatureValue", DsNs);
                svEl.SetAttribute("Id", svId);
                svEl.InnerText = Convert.ToBase64String(sigBytes);
                // Insert after SignedInfo, before KeyInfo
                sigEl.InsertBefore(svEl, kiEl);

                // ── Importar y anexar al documento original ───────────────────────
                var importedSig = (XmlElement)xmlDoc.ImportNode(sigEl, true);
                xmlDoc.DocumentElement.AppendChild(importedSig);

                // ── Serializar con UTF-8 real (StringWriter usa UTF-16 internamente) ─
                using var ms = new System.IO.MemoryStream();
                using var xw = XmlWriter.Create(ms, new XmlWriterSettings
                {
                    Indent = false,
                    Encoding = new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
                    OmitXmlDeclaration = false
                });
                xmlDoc.Save(xw);
                xw.Flush();
                xmlSigned = System.Text.Encoding.UTF8.GetString(ms.ToArray());
                cert.Dispose();
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error al firmar: {ex.Message}\n{ex.StackTrace}");
                xmlSigned = null;
                return false;
            }
        }

        // ── Helpers ──────────────────────────────────────────────────────────────

        private static XmlElement BuildKeyInfo(XmlDocument d, X509Certificate2 cert, string certId)
        {
            var ki = d.CreateElement("ds", "KeyInfo", DsNs);
            ki.SetAttribute("Id", certId);

            var x509data = d.CreateElement("ds", "X509Data", DsNs);
            var x509cert = d.CreateElement("ds", "X509Certificate", DsNs);
            x509cert.InnerText = Convert.ToBase64String(cert.RawData);
            x509data.AppendChild(x509cert);
            ki.AppendChild(x509data);

            var kv = d.CreateElement("ds", "KeyValue", DsNs);
            var rsaKv = d.CreateElement("ds", "RSAKeyValue", DsNs);
            var rsa = cert.GetRSAPublicKey()!;
            var p = rsa.ExportParameters(false);
            var mod = d.CreateElement("ds", "Modulus", DsNs);
            mod.InnerText = Convert.ToBase64String(p.Modulus!);
            var exp = d.CreateElement("ds", "Exponent", DsNs);
            exp.InnerText = Convert.ToBase64String(p.Exponent!);
            rsaKv.AppendChild(mod);
            rsaKv.AppendChild(exp);
            kv.AppendChild(rsaKv);
            ki.AppendChild(kv);
            return ki;
        }

        private XmlElement BuildSignedProperties(XmlDocument d, X509Certificate2 cert,
            string sigId, string spId, string certId, string refId)
        {
            var sp = d.CreateElement("etsi", "SignedProperties", EtsiNs);
            sp.SetAttribute("Id", spId);

            var ssp = d.CreateElement("etsi", "SignedSignatureProperties", EtsiNs);

            var st = d.CreateElement("etsi", "SigningTime", EtsiNs);
            st.InnerText = GetEcuadorSigningTime();
            ssp.AppendChild(st);

            var sc = d.CreateElement("etsi", "SigningCertificate", EtsiNs);
            var ce = d.CreateElement("etsi", "Cert", EtsiNs);
            var cd = d.CreateElement("etsi", "CertDigest", EtsiNs);
            var dm = d.CreateElement("ds", "DigestMethod", DsNs);
            dm.SetAttribute("Algorithm", Sha1Uri);
            var dv = d.CreateElement("ds", "DigestValue", DsNs);
            using (var sha1 = SHA1.Create())
                dv.InnerText = Convert.ToBase64String(sha1.ComputeHash(cert.RawData));
            cd.AppendChild(dm); cd.AppendChild(dv);
            ce.AppendChild(cd);

            var iS = d.CreateElement("etsi", "IssuerSerial", EtsiNs);
            var xn = d.CreateElement("ds", "X509IssuerName", DsNs);
            xn.InnerText = cert.IssuerName.Name;
            var xs = d.CreateElement("ds", "X509SerialNumber", DsNs);
            xs.InnerText = HexToDec(cert.SerialNumber);
            iS.AppendChild(xn); iS.AppendChild(xs);
            ce.AppendChild(iS);
            sc.AppendChild(ce);
            ssp.AppendChild(sc);
            sp.AppendChild(ssp);

            var sdop = d.CreateElement("etsi", "SignedDataObjectProperties", EtsiNs);
            var dof  = d.CreateElement("etsi", "DataObjectFormat", EtsiNs);
            dof.SetAttribute("ObjectReference", $"#{refId}");
            var desc = d.CreateElement("etsi", "Description", EtsiNs);
            desc.InnerText = "contenido comprobante";
            dof.AppendChild(desc);
            var mt = d.CreateElement("etsi", "MimeType", EtsiNs);
            mt.InnerText = "text/xml";
            dof.AppendChild(mt);
            sdop.AppendChild(dof);
            sp.AppendChild(sdop);
            return sp;
        }

        private static XmlElement BuildReference(XmlDocument d, string? id, string uri,
            string? type, byte[] digest)
        {
            var r = d.CreateElement("ds", "Reference", DsNs);
            if (id != null) r.SetAttribute("Id", id);
            r.SetAttribute("URI", uri);
            if (type != null) r.SetAttribute("Type", type);
            var dm = d.CreateElement("ds", "DigestMethod", DsNs);
            dm.SetAttribute("Algorithm", Sha1Uri);
            r.AppendChild(dm);
            var dv = d.CreateElement("ds", "DigestValue", DsNs);
            dv.InnerText = Convert.ToBase64String(digest);
            r.AppendChild(dv);
            return r;
        }

        private static XmlElement Elem(XmlDocument d, string prefix, string local, string ns,
            string attr, string attrVal)
        {
            var e = d.CreateElement(prefix, local, ns);
            e.SetAttribute(attr, attrVal);
            return e;
        }

        /// <summary>C14N SHA-1 digest of a single XmlElement (treated as document root).</summary>
        private static byte[] Sha1C14NDigest(XmlElement el)
        {
            var bytes = C14NBytes(el);
            using var sha1 = SHA1.Create();
            return sha1.ComputeHash(bytes);
        }

        /// <summary>C14N SHA-1 digest of the root element of an XmlDocument (enveloped = whole doc).</summary>
        private static byte[] Sha1C14NDigestDoc(XmlDocument doc)
        {
            var bytes = C14NBytes(doc.DocumentElement!);
            using var sha1 = SHA1.Create();
            return sha1.ComputeHash(bytes);
        }

        private static byte[] C14NBytes(XmlElement el)
        {
            // Wrap in a fresh document so C14N treats it as root (no inherited namespaces)
            var tmp = new XmlDocument { PreserveWhitespace = true };
            tmp.LoadXml(el.OuterXml);
            var t = new XmlDsigC14NTransform();
            t.LoadInput(tmp);
            using var ms = (MemoryStream)t.GetOutput(typeof(Stream));
            return ms.ToArray();
        }

        private static string HexToDec(string hex)
        {
            BigInteger v = 0;
            foreach (var c in hex) v = v * 16 + Convert.ToInt32(c.ToString(), 16);
            return v.ToString();
        }

        private static string GetEcuadorSigningTime()
        {
            // Try IANA id first (Linux/macOS), then Windows id, then fixed -05:00 offset as fallback.
            TimeZoneInfo tz =
                TryGetTz("America/Guayaquil") ??
                TryGetTz("SA Pacific Standard Time") ??
                TimeZoneInfo.CreateCustomTimeZone("EC", TimeSpan.FromHours(-5), "EC", "EC");
            return TimeZoneInfo.ConvertTime(DateTimeOffset.UtcNow, tz).ToString("yyyy-MM-ddTHH:mm:ss-05:00");
        }

        private static TimeZoneInfo? TryGetTz(string id)
        {
            try { return TimeZoneInfo.FindSystemTimeZoneById(id); }
            catch { return null; }
        }
    }
}
