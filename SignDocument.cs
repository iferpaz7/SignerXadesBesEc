using es.mityc.firmaJava.libreria.xades;
using es.mityc.javasign.pkstore;
using es.mityc.javasign.pkstore.keystore;
using es.mityc.javasign.xml.refs;
using java.io;
using java.security;
using java.security.cert;
using javax.xml.parsers;
using org.apache.xml.security.utils;
using org.w3c.dom;
using System;
using System.IO;
using System.Text;
using Console = System.Console;

namespace SignerXadesBesEc
{
    /// <summary>
    /// Clase responsable de realizar el proceso de firma XAdES-BES sobre un documento XML.
    /// Envuelve la interacción con las librerías Java (portadas) necesarias para cargar el certificado,
    /// preparar el XML y generar la firma embebida (enveloped).
    /// </summary>
    public class SignDocument
    {
        /// <summary>
        /// Carga el certificado desde un arreglo de bytes de un archivo PKCS#12 (p12/pfx),
        /// obteniendo el certificado X509, la clave privada y el proveedor criptográfico.
        /// </summary>
        /// <param name="claveArvhivoP12">Contraseña del archivo PKCS#12.</param>
        /// <param name="certificate">Contenido binario del archivo PKCS#12.</param>
        /// <param name="privateKey">(out) Clave privada asociada al certificado de firma.</param>
        /// <param name="provider">(out) Proveedor criptográfico utilizado por la librería de firma.</param>
        /// <returns>Certificado X509 listo para la firma; null si no se pudo cargar o no hay certificados de firma.</returns>
        private X509Certificate _LoadCertificate(string claveArvhivoP12, byte[] certificate,
            out PrivateKey privateKey, out Provider provider)
        {
            provider = null;
            privateKey = null;

            // Se utiliza MemoryStream para mantener consistencia (aunque la librería Java opera directamente con el byte[])
            using (var memoryStream = new MemoryStream(certificate))
            {
                // Se crea un InputStream Java a partir del contenido del certificado.
                var stream = new ByteArrayInputStream(certificate);

                // Instancia un KeyStore de tipo PKCS12 y lo carga con la contraseña indicada.
                var instance = KeyStore.getInstance("PKCS12");
                instance.load(stream, claveArvhivoP12.ToCharArray());

                // Administrador de almacén que permitirá obtener certificados y sus claves relacionadas.
                var pkStoreManager = (IPKStoreManager)new KSStore(instance, new PassStoreKS(claveArvhivoP12));
                var signCertificates = pkStoreManager.getSignCertificates();

                // Se toma el primer certificado de firma disponible (si existe).
                if (signCertificates.size() > 0)
                {
                    var xc = (X509Certificate)signCertificates.get(0);
                    privateKey = pkStoreManager.getPrivateKey(xc); // Obtiene clave privada asociada.
                    provider = pkStoreManager.getProvider(xc);     // Obtiene el proveedor criptográfico.
                    return xc;
                }

                // Cierra el stream antes de salir si no hay certificado.
                stream.close();
                return null;
            }
        }

        /// <summary>
        /// Convierte una cadena XML en un objeto Document (DOM) que las librerías de firma pueden manipular.
        /// </summary>
        /// <param name="xml">Contenido XML en texto.</param>
        /// <returns>Instancia Document; null si ocurre un error de análisis.</returns>
        private Document LoadXmlFromString(string xml)
        {
            try
            {
                var factory = DocumentBuilderFactory.newInstance();
                factory.setNamespaceAware(true); // Importante para la correcta firma XML con namespaces.
                var builder = factory.newDocumentBuilder();
                var documento = builder.parse(new ByteArrayInputStream(Encoding.UTF8.GetBytes(xml)));
                return documento;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error leyendo el XML: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Convierte un objeto Document (DOM) en su representación binaria (bytes) UTF-8 del XML firmado.
        /// </summary>
        /// <param name="doc">Documento firmado o modificado por el proceso.</param>
        /// <returns>Arreglo de bytes del XML; null si falla la serialización.</returns>
        private byte[] GetBytesFromDocument(Document doc)
        {
            try
            {
                var baos = new ByteArrayOutputStream();
                XMLUtils.outputDOM(doc, baos, true); // true = con declaración XML / formato adecuado.
                return baos.toByteArray();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error obteniendo la representación firmada del comprobante: " + ex.Message);
                return null;
            }
        }

        /// <summary>
        /// Firma un documento XML en formato XAdES-BES (enveloped) utilizando el certificado proporcionado.
        /// </summary>
        /// <param name="xmlUnsigned">XML original sin firmar. Debe contener el nodo 'comprobante' que será el nodo padre de la firma.</param>
        /// <param name="password">Contraseña del certificado (archivo PKCS#12).</param>
        /// <param name="certificate">Bytes del archivo PKCS#12 que contiene certificado y clave privada.</param>
        /// <param name="xmlSigned">(ref) Resultado del XML firmado si el proceso finaliza correctamente.</param>
        /// <returns>true si la firma se generó correctamente; false en caso de error.</returns>
        public bool Sign(string xmlUnsigned, string password, byte[] certificate, ref string xmlSigned)
        {
            var signed = true; // Indicador de estado del proceso.

            // 1. Cargar certificado y obtener clave privada / proveedor.
            var certificadoFirma = _LoadCertificate(password, certificate, out var privateKey, out var provider);

            // 2. Validar que el certificado se haya cargado correctamente.
            if (certificadoFirma == null)
            {
                xmlSigned = null;
                return false;
            }

            try
            {
                // 3. Parsear el XML de entrada a un Document DOM.
                var document = LoadXmlFromString(xmlUnsigned);
                if (document == null)
                {
                    xmlSigned = null;
                    return false;
                }

                // 4. Preparar objeto DataToSign configurando formato, esquema y tipo de firma.
                var dataToSign = new DataToSign();
                dataToSign.setXadesFormat(EnumFormatoFirma.XAdES_BES); // Formato XAdES-BES.
                dataToSign.setEsquema(XAdESSchemas.XAdES_132);         // Esquema a utilizar.
                dataToSign.setXMLEncoding("UTF-8");                   // Codificación del XML.
                dataToSign.setEnveloped(true);                         // Firma de tipo enveloped (inserta firma dentro del XML).

                // 5. Indicar el objeto a firmar: el nodo 'comprobante'.
                dataToSign.addObject(new ObjectToSign(new InternObjectToSign("comprobante"),
                    "contenido comprobante", null, "text/xml", null));
                dataToSign.setParentSignNode("comprobante");          // Nodo padre donde se anclará la firma.
                dataToSign.setDocument(document);                      // Documento que será firmado.

                // 6. Ejecutar la firma con la librería.
                var signXml = new FirmaXML();
                var objArray = signXml.signFile(certificadoFirma, dataToSign, privateKey, provider);
                // objArray puede contener el Document firmado y otros datos (no se usa explícitamente aquí).

                // 7. Convertir el Document firmado a cadena.
                var byteXmlSigned = GetBytesFromDocument(document);
                switch (byteXmlSigned)
                {
                    case null:
                        xmlSigned = null;
                        return false;
                    default:
                        xmlSigned = Encoding.UTF8.GetString(byteXmlSigned);
                        break;
                }
            }
            catch (Exception ex)
            {
                signed = false;
                Console.WriteLine("Error al firmar el comprobante: " + ex.Message);
            }
            return signed;
        }
    }
}