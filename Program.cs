using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace SignerXadesBesEc
{
    public static class Program
    {
        // Console entry point to demonstrate signing usage
        // Args (optional, will prompt if missing):
        //   <p12-path> <password> [xml-input-path] [xml-output-path]
        public static int Main(string[] args)
        {
            try
            {
                string p12Path;
                string password;
                string xmlInputPath;
                string xmlOutputPath;

                if (!TryParseArgs(args, out p12Path, out password, out xmlInputPath, out xmlOutputPath))
                {
                    Console.WriteLine("Interactive mode (press ENTER to accept defaults / skip optional values)\n");
                    p12Path = ReadRequiredPath("Enter path to P12/PFX certificate file: ", mustExist: true);
                    password = ReadNonEmpty("Enter certificate password: ");
                    xmlInputPath = ReadOptionalPath("Enter XML input file path (leave empty to use sample XML): ");
                    xmlOutputPath = ReadOptional("Enter output path for signed XML (leave empty to print to console): ");
                }

                if (!File.Exists(p12Path))
                {
                    Console.WriteLine("Certificate file not found: " + p12Path);
                    return 2;
                }

                string xmlToSign;
                if (!string.IsNullOrWhiteSpace(xmlInputPath))
                {
                    if (!File.Exists(xmlInputPath))
                    {
                        Console.WriteLine("XML input file not found: " + xmlInputPath);
                        return 3;
                    }
                    xmlToSign = File.ReadAllText(xmlInputPath);
                }
                else
                {
                    xmlToSign = "<comprobante><info>Sample</info></comprobante>"; // minimal sample
                }

                var certificateBytes = File.ReadAllBytes(p12Path);

                if (!ValidateCertificate(certificateBytes, password))
                    return 4; // message already printed

                var signer = new SignDocument();
                string xmlSigned = null;
                var ok = signer.Sign(xmlToSign, password, certificateBytes, ref xmlSigned);
                if (!ok || string.IsNullOrEmpty(xmlSigned))
                {
                    Console.WriteLine("Signing failed.");
                    return 6;
                }

                if (!string.IsNullOrWhiteSpace(xmlOutputPath))
                {
                    try
                    {
                        File.WriteAllText(xmlOutputPath, xmlSigned);
                        Console.WriteLine("Signed XML written: " + xmlOutputPath);
                    }
                    catch (Exception ioEx)
                    {
                        Console.WriteLine("Could not write output file: " + ioEx.Message);
                        return 7;
                    }
                }
                else
                {
                    Console.WriteLine(xmlSigned);
                }
                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Unexpected error: " + ex.Message);
                return 9;
            }
        }

        private static bool TryParseArgs(string[] args, out string p12Path, out string password, out string xmlInput, out string xmlOutput)
        {
            p12Path = password = xmlInput = xmlOutput = null;
            if (args == null || args.Length < 2)
            {
                Console.WriteLine("Insufficient arguments provided. Switching to interactive mode.");
                return false;
            }
            p12Path = args[0];
            password = args[1];
            xmlInput = args.Length > 2 ? args[2] : null;
            xmlOutput = args.Length > 3 ? args[3] : null;
            return true;
        }

        private static bool ValidateCertificate(byte[] certBytes, string password)
        {
            try
            {
                var tempCert = new X509Certificate2(certBytes, password, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
                var exp = DateTime.Parse(tempCert.GetExpirationDateString());
                if (DateTime.Now > exp)
                {
                    Console.WriteLine("Error: Certificate is expired (" + exp + ")");
                    return false;
                }
                return true;
            }
            catch (Exception exCert)
            {
                Console.WriteLine("Failed to load certificate: " + exCert.Message);
                return false;
            }
        }

        private static string ReadRequiredPath(string prompt, bool mustExist)
        {
            while (true)
            {
                Console.Write(prompt);
                var input = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(input))
                {
                    Console.WriteLine("Value is required.");
                    continue;
                }
                if (mustExist && !File.Exists(input))
                {
                    Console.WriteLine("File does not exist: " + input);
                    continue;
                }
                return input.Trim();
            }
        }

        private static string ReadNonEmpty(string prompt)
        {
            while (true)
            {
                Console.Write(prompt);
                var input = Console.ReadLine();
                if (!string.IsNullOrEmpty(input))
                    return input;
                Console.WriteLine("Value is required.");
            }
        }

        private static string ReadOptional(string prompt)
        {
            Console.Write(prompt);
            var input = Console.ReadLine();
            return string.IsNullOrWhiteSpace(input) ? null : input.Trim();
        }

        private static string ReadOptionalPath(string prompt)
        {
            while (true)
            {
                Console.Write(prompt);
                var input = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(input))
                    return null;
                if (!File.Exists(input))
                {
                    Console.WriteLine("File does not exist (leave empty to skip): " + input);
                    continue;
                }
                return input.Trim();
            }
        }
    }
}
