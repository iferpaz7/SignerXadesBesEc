using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace SignerXadesBesEc
{
    /// <summary>
    /// Firma comprobantes electrónicos XML para SRI Ecuador (XAdES-BES).
    ///
    /// Uso: <cert.p12> <password> <claveAcceso49> [xml-input] [xml-output]
    ///
    /// Si no se proveen suficientes argumentos, entra en modo interactivo.
    /// </summary>
    public static class Program
    {
        public static int Main(string[] args)
            => MainAsync(args).GetAwaiter().GetResult();

        private static async Task<int> MainAsync(string[] args)
        {
            try
            {
                string p12Path;
                string password;
                string claveAcceso;
                string? xmlInputPath;
                string? xmlOutputPath;

                if (!TryParseArgs(args, out p12Path, out password, out claveAcceso, out xmlInputPath, out xmlOutputPath))
                {
                    Console.WriteLine("=== SignerXadesBesEc SRI Ecuador — Modo interactivo ===");
                    Console.WriteLine("(ENTER para omitir opcionales)\n");
                    p12Path       = ReadRequiredPath("Ruta del certificado (.p12 / .pfx): ", mustExist: true);
                    password      = ReadNonEmpty("Contraseña del certificado: ");
                    claveAcceso   = ReadClaveAcceso("Clave de acceso SRI (49 dígitos): ");
                    xmlInputPath  = ReadOptionalPath("Ruta del XML a firmar (ENTER para XML de prueba): ");
                    xmlOutputPath = ReadOptional("Ruta del XML firmado de salida (ENTER para imprimir en consola): ");
                }

                if (!File.Exists(p12Path))
                {
                    Console.Error.WriteLine("Error: Certificado no encontrado: " + p12Path);
                    return 2;
                }

                var certificateBytes = File.ReadAllBytes(p12Path);

                if (!ValidateCertificate(certificateBytes, password))
                    return 4;

                string xmlToSign = LoadXml(xmlInputPath);
                if (xmlToSign == null!)
                    return 3;

                string? xmlSigned = null;
                Console.WriteLine("Firmando: clave de acceso " + claveAcceso);
                var signer = new SriSigner();
                bool ok = signer.Sign(xmlToSign, password, certificateBytes, claveAcceso, ref xmlSigned);

                if (!ok || string.IsNullOrEmpty(xmlSigned))
                {
                    Console.Error.WriteLine("Error: El proceso de firma falló.");
                    return 6;
                }

                if (!string.IsNullOrWhiteSpace(xmlOutputPath))
                {
                    File.WriteAllText(xmlOutputPath, xmlSigned);
                    Console.WriteLine("XML firmado escrito en: " + xmlOutputPath);
                }
                else
                {
                    Console.WriteLine(xmlSigned);
                }

                // Detectar ambiente desde la clave de acceso (posición 23: '1'=pruebas, '2'=producción)
                bool esProduccion = claveAcceso[23] == '2';
                    string sriUrl = esProduccion ? SriReceptionService.UrlProduccion : SriReceptionService.UrlPruebas;
                    string ambienteLabel = esProduccion ? "PRODUCCIÓN" : "PRUEBAS";

                    Console.WriteLine($"\nAmbiente detectado: {ambienteLabel}");
                    Console.WriteLine("Enviando al SRI: " + sriUrl);
                    var sriService = new SriReceptionService();
                    var resp = await sriService.ReceptionAsync(xmlSigned, sriUrl);

                    Console.WriteLine("Estado       : " + resp.Estado);
                    if (!string.IsNullOrEmpty(resp.Identificador))
                        Console.WriteLine("Identificador: " + resp.Identificador);
                    if (!string.IsNullOrEmpty(resp.Message))
                        Console.WriteLine("Mensaje      : " + resp.Message);
                    if (!string.IsNullOrEmpty(resp.InformacionAdicional))
                        Console.WriteLine("Info adicional: " + resp.InformacionAdicional);
                    if (!string.IsNullOrEmpty(resp.Tipo))
                        Console.WriteLine("Tipo         : " + resp.Tipo);
                    if (!string.IsNullOrEmpty(resp.XmlSri))
                    {
                        Console.WriteLine("\n--- Respuesta raw SRI ---");
                        Console.WriteLine(resp.XmlSri);
                    }

                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error inesperado: " + ex.Message);
                return 9;
            }
        }

        // ── Helpers ────────────────────────────────────────────────────────────────

        /// <summary>
        /// Intenta parsear argumentos de línea de comandos.
        /// Detects SRI mode when 3rd arg is a 49-digit string.
        /// </summary>
        private static bool TryParseArgs(
            string[] args,
            out string p12Path,
            out string password,
            out string claveAcceso,
            out string? xmlInput,
            out string? xmlOutput)
        {
            p12Path = password = claveAcceso = string.Empty;
            xmlInput = xmlOutput = null;

            if (args == null || args.Length < 3) return false;

            p12Path     = args[0];
            password    = args[1];

            if (args[2].Length != 49 || !IsAllDigits(args[2]))
            {
                Console.Error.WriteLine("Error: El tercer argumento debe ser la clave de acceso SRI (49 dígitos).");
                return false;
            }

            claveAcceso = args[2];
            xmlInput    = args.Length > 3 ? args[3] : null;
            xmlOutput   = args.Length > 4 ? args[4] : null;
            return true;
        }

        private static bool IsAllDigits(string s)
        {
            foreach (var c in s)
                if (c < '0' || c > '9') return false;
            return true;
        }

        private static string LoadXml(string? xmlInputPath)
        {
            if (string.IsNullOrWhiteSpace(xmlInputPath))
            {
                // XML de prueba mínimo compatible con SRI (tiene id="comprobante")
                return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                       "<factura id=\"comprobante\" version=\"1.1.0\">" +
                       "<infoTributaria><ambiente>1</ambiente><tipoEmision>1</tipoEmision>" +
                       "<razonSocial>EMPRESA PRUEBA</razonSocial><ruc>9999999999001</ruc>" +
                       "<claveAcceso>0101202401099999999900110010010000000011234567814</claveAcceso>" +
                       "<codDoc>01</codDoc><estab>001</estab><ptoEmi>001</ptoEmi>" +
                       "<secuencial>000000001</secuencial></infoTributaria>" +
                       "<infoFactura><fechaEmision>01/01/2024</fechaEmision>" +
                       "<totalSinImpuestos>100.00</totalSinImpuestos>" +
                       "<importeTotal>112.00</importeTotal></infoFactura>" +
                       "</factura>";
            }

            if (!File.Exists(xmlInputPath))
            {
                Console.Error.WriteLine("Error: XML no encontrado: " + xmlInputPath);
                return null!;
            }

            return File.ReadAllText(xmlInputPath);
        }

        private static bool ValidateCertificate(byte[] certBytes, string password)
        {
            try
            {
                using var cert = X509CertificateLoader.LoadPkcs12(certBytes, password,
                    X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);

                if (DateTime.Now > cert.NotAfter)
                {
                    Console.Error.WriteLine($"Error: Certificado expirado ({cert.NotAfter:yyyy-MM-dd})");
                    return false;
                }

                if (cert.GetRSAPrivateKey() == null)
                {
                    Console.Error.WriteLine("Error: El certificado no usa RSA. SRI Ecuador requiere certificados RSA.");
                    return false;
                }

                Console.WriteLine($"Certificado OK — Sujeto: {cert.Subject}");
                Console.WriteLine($"  Emitido por: {cert.Issuer}");
                Console.WriteLine($"  Válido hasta: {cert.NotAfter:yyyy-MM-dd}");
                return true;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error cargando certificado: " + ex.Message);
                return false;
            }
        }

        private static string ReadRequiredPath(string prompt, bool mustExist)
        {
            while (true)
            {
                Console.Write(prompt);
                var input = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(input)) { Console.WriteLine("Valor requerido."); continue; }
                if (mustExist && !File.Exists(input)) { Console.WriteLine("Archivo no existe: " + input); continue; }
                return input.Trim();
            }
        }

        private static string ReadNonEmpty(string prompt)
        {
            while (true)
            {
                Console.Write(prompt);
                var input = Console.ReadLine();
                if (!string.IsNullOrEmpty(input)) return input;
                Console.WriteLine("Valor requerido.");
            }
        }

        private static string? ReadOptional(string prompt)
        {
            Console.Write(prompt);
            var input = Console.ReadLine();
            return string.IsNullOrWhiteSpace(input) ? null : input.Trim();
        }

        private static string? ReadOptionalPath(string prompt)
        {
            while (true)
            {
                Console.Write(prompt);
                var input = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(input)) return null;
                if (!File.Exists(input)) { Console.WriteLine("Archivo no existe (ENTER para saltar): " + input); continue; }
                return input.Trim();
            }
        }

        private static string ReadClaveAcceso(string prompt)
        {
            while (true)
            {
                Console.Write(prompt);
                var input = Console.ReadLine()?.Trim() ?? string.Empty;
                if (input.Length == 49 && IsAllDigits(input)) return input;
                Console.WriteLine("Debe ser exactamente 49 dígitos numéricos.");
            }
        }
    }
}
