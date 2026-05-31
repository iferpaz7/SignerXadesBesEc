using System;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace SignerXadesBesEc
{
    /// <summary>
    /// Envía el XML firmado al servicio de recepción del SRI Ecuador y parsea la respuesta.
    /// </summary>
    public class SriReceptionService
    {
        // URLs de recepción SRI
        public const string UrlPruebas    = "https://celcer.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline";
        public const string UrlProduccion = "https://cel.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline";

        public async Task<SriResponse> ReceptionAsync(string xmlSigned, string url)
        {
            var responseSri = new SriResponse();
            try
            {
                var soapBody =
                    $"<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:ec=\"http://ec.gob.sri.ws.recepcion\">" +
                    $"<soapenv:Header/>" +
                    $"<soapenv:Body>" +
                    $"<ec:validarComprobante>" +
                    $"<xml>{Convert.ToBase64String(Encoding.UTF8.GetBytes(xmlSigned))}</xml>" +
                    $"</ec:validarComprobante>" +
                    $"</soapenv:Body>" +
                    $"</soapenv:Envelope>";

                using var httpClient = new HttpClient();
                httpClient.Timeout = TimeSpan.FromSeconds(30);

                using var response = await httpClient.PostAsync(
                    url,
                    new StringContent(soapBody, Encoding.UTF8, "text/xml"));

                await using var streamResponse = await response.Content.ReadAsStreamAsync();
                using var streamReader = new StreamReader(streamResponse);
                responseSri.XmlSri = await streamReader.ReadToEndAsync();

                if (IsValidXml(responseSri.XmlSri))
                {
                    var xdoc = new XmlDocument();
                    xdoc.LoadXml(responseSri.XmlSri);

                    var xEstado = xdoc.GetElementsByTagName("estado");
                    responseSri.Estado = xEstado.Count > 0 ? xEstado[0]!.InnerText : string.Empty;

                    // Parse mensajes when DEVUELTA *or* when SRI omits <estado> but returns <mensajes>
                    var mensajesNodes = xdoc.GetElementsByTagName("mensaje");
                    if (responseSri.Estado == "DEVUELTA" || (string.IsNullOrEmpty(responseSri.Estado) && mensajesNodes.Count > 0))
                    {
                        if (string.IsNullOrEmpty(responseSri.Estado))
                            responseSri.Estado = "DEVUELTA";

                        var mensajes = mensajesNodes;
                        if (mensajes.Count > 0)
                        {
                            var messageNode = mensajes[0] as XmlElement;
                            if (messageNode?.ChildNodes != null)
                                foreach (XmlNode nodo in messageNode.ChildNodes)
                                    switch (nodo.Name)
                                    {
                                        case "identificador":
                                            responseSri.Identificador = nodo.InnerText;
                                            break;
                                        case "mensaje":
                                            responseSri.Message = nodo.InnerText;
                                            break;
                                        case "informacionAdicional":
                                            responseSri.InformacionAdicional = nodo.InnerText;
                                            break;
                                        case "tipo":
                                            responseSri.Tipo = nodo.InnerText;
                                            break;
                                    }
                        }
                    }
                }
                else
                {
                    responseSri.Estado  = "ERROR";
                    responseSri.Message = "SRI no se encuentra en línea";
                }
            }
            catch (TaskCanceledException)
            {
                responseSri.Estado  = "ERROR";
                responseSri.Message = "Tiempo de espera agotado al conectar con SRI";
            }
            catch (Exception)
            {
                responseSri.Estado  = "ERROR";
                responseSri.Message = "SRI no se encuentra en línea";
            }

            return responseSri;
        }

        private static bool IsValidXml(string xml)
        {
            if (string.IsNullOrWhiteSpace(xml))
                return false;
            try
            {
                var doc = new XmlDocument();
                doc.LoadXml(xml);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
