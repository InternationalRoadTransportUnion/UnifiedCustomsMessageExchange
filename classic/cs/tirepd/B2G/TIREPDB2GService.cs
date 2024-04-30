using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.Threading;
using System.Xml.Serialization;

using B2G.G2B;
using IRU.Encryption;
using TIREPD.Messages;

namespace B2G
{
    [ServiceBehavior(Namespace = "http://www.iru.org", ConfigurationName = "TIREPDB2GService")]
    public class TIREPDB2GService : ITIREPDB2GService
    {        
        public TIREPDB2GUploadAck TIREPDB2G(TIREPDB2GUploadParams su)
        {
            try
            {
                string messageContent = DecryptMessageContent(su);
                ProcessMessageContent(su.MessageName,messageContent);
                return new TIREPDB2GUploadAck(AckReturnCode.Success, su.SubscriberMessageID);
            }
            catch (B2GException ex)
            {
                Log(string.Format("ReturnCode {0} : {1} - {2}\r\n{3}", (int)ex.ReturnCode, ex.ReturnCode.ToString(), ex.Message, ex.StackTrace), EventLogEntryType.Error);
                return new TIREPDB2GUploadAck(ex.ReturnCode, su.SubscriberMessageID);
            }
            catch (Exception ex)
            {
                Log(ex.Message + "\r\n" + ex.StackTrace, EventLogEntryType.Error);
                return new TIREPDB2GUploadAck(AckReturnCode.AnyUnclassifiedError, su.SubscriberMessageID);
            }
        }

        private void Log(string message, EventLogEntryType entryType)
        {
            if (entryType == EventLogEntryType.Error)
                Trace.WriteLine("[TIREPDB2GDotNET] ERROR: " + message + "\r\n");
            else
                Trace.WriteLine("[TIREPDB2GDotNET] " + message + "\r\n");
        }

        private string DecryptMessageContent(TIREPDB2GUploadParams su)
        {
            string file = ConfigurationManager.AppSettings["B2GCertificatePath"];
            string password = ConfigurationManager.AppSettings["B2GCertificatePassword"];
            if (String.IsNullOrEmpty(password))
                password = null;
            X509Certificate2 cert = EncryptionHelper.GetCertificateFromFile(file, password);
            try
            {
                ValidateParams(su, cert.PublicKey.Key.KeySize);
                return EncryptionHelper.X509DecryptString(su.ESessionKey, su.MessageContent, su.CertificateID, cert);
            }
            catch (B2GException ex)
            {
                Log(ex.Message + "\r\n" + ex.StackTrace, EventLogEntryType.Error);
                throw;
            }
            catch (Exception ex)
            {
                Log(ex.Message, EventLogEntryType.Error);
                throw new B2GException(AckReturnCode.EncryptionDecryptionFailure, ex);
            }
        }

        private void ValidateParams(TIREPDB2GUploadParams su, int keyLength)
        {
            if (string.IsNullOrEmpty(su.SubscriberID) || su.SubscriberID != ConfigurationManager.AppSettings["SubscriberID"])
                throw new B2GException(AckReturnCode.MissingOrInvalidSubscriberID);
            if (string.IsNullOrEmpty(su.CertificateID))
                throw new B2GException(AckReturnCode.MissingOrInvalidCertificateID);
            if (su.ESessionKey == null || (keyLength > 0 && su.ESessionKey.Length * 8 != keyLength))
                throw new B2GException(AckReturnCode.MissingOrInvalidESessionKey);
            if (string.IsNullOrEmpty(su.SubscriberMessageID))
                throw new B2GException(AckReturnCode.MissingOrInvalidSubscriberMessageID);
            if (string.IsNullOrEmpty(su.InformationExchangeVersion) || su.InformationExchangeVersion != "1.0.0")
                throw new B2GException(AckReturnCode.MissingOrInvalidInformationExchangeVersion);
            if (string.IsNullOrEmpty(su.MessageName))
                throw new B2GException(AckReturnCode.MissingOrInvalidMessageName);
            DateTime dateValue;
            if (!DateTime.TryParse(su.TimeSent, out dateValue))
                throw new B2GException(AckReturnCode.MissingOrInvalidTimeSent);
            if (su.MessageContent == null || su.MessageContent.Length <= 0)
                throw new B2GException(AckReturnCode.MissingOrInvalidMessageContents);
        }

        private void ProcessMessageContent(string messageName, string messageContent)
        {             
            Log("Message Content : " + messageContent, EventLogEntryType.Information);
            if (messageName == "TIRPreDeclaration")
            {
                EPD015 epd015 = (EPD015)Deserialize(messageContent, typeof(EPD015));
                Log(string.Format("TIR Pre-Declaration received LRN = {0}", epd015.HEAHEA.RefNumHEA4), EventLogEntryType.Information);
                Thread thread = new Thread(new ParameterizedThreadStart(ProcessResponseAsynchronously));
                thread.Start(epd015);
            }
            else if (messageName == "TIRPreDeclarationCancellationNotice")
            {
                EPD014 epd014 = (EPD014)Deserialize(messageContent, typeof(EPD014));
                Log(string.Format("TIR Cancellation Request received MRN = {0}", epd014.HEAHEA.DocNumHEA5), EventLogEntryType.Information);
                Thread thread = new Thread(new ParameterizedThreadStart(ProcessResponseAsynchronously));
                thread.Start(epd014);
            }
            else if (messageName == "TIRPreDeclarationAmendment")
            {
                EPD013 epd013 = (EPD013)Deserialize(messageContent, typeof(EPD013));
                Log(string.Format("TIR Amendment received MRN = {0}", epd013.HEAHEA.DocNumHEA5), EventLogEntryType.Information);
                Thread thread = new Thread(new ParameterizedThreadStart(ProcessResponseAsynchronously));
                thread.Start(epd013);
            }
            else if (messageName == "TIRPreDeclarationInfOnNonArrMov")
            {
                EPD141 epd141 = (EPD141)Deserialize(messageContent, typeof(EPD141));
                Log(string.Format("TIR Information on non-arrived movement received MRN = {0}", epd141.HEAHEA.DocNumHEA5), EventLogEntryType.Information);
                Thread thread = new Thread(new ParameterizedThreadStart(ProcessResponseAsynchronously));
                thread.Start(epd141);
            }
            else
                throw new B2GException(string.Format("Incorrect value for MessageName {0}",messageName), AckReturnCode.AnyUnclassifiedError);
        }

        private void ProcessResponseAsynchronously(object epd)
        {
            try
            {
                if (epd is EPD015)
                {
                    EPD015 epd015 = (EPD015)epd;

                    Thread.Sleep(2000); // Please write/call your code to validate the structure of the message and to persist it in DB here instead of doing a simple wait
                    bool success = true;

                    if (success)
                    {
                        EPD928 epd928 = BuildEPD928(epd015);
                        string response = Serialize(epd928);
                        Log("Response Content : " + response, EventLogEntryType.Information);
                        TIREPDG2BUploadAck result = SendG2BResponse("TIRPreDeclarationReceived", response);

                        if (result.ReturnCode == (int)AckReturnCode.Success)
                            Log(string.Format("EPD928 transmitted with success for TIR Pre-Declaration {0}", epd928.HEAHEA.RefNumHEA4), EventLogEntryType.Information);
                        else
                            Log(string.Format("G2B error returned for TIR Pre-Declaration {0} : return code {1}", epd928.HEAHEA.RefNumHEA4, result.ReturnCode), EventLogEntryType.Information);
                    }
                    else
                    {
                        EPD917 epd917 = BuildEPD917(epd015);
                        string response = Serialize(epd917);
                        Log("Response Content : " + response, EventLogEntryType.Information);
                        TIREPDG2BUploadAck result = SendG2BResponse("TIRPreDeclarationError", response);

                        if (result.ReturnCode == (int)AckReturnCode.Success)
                            Log(string.Format("EPD917 transmitted with success for TIR Pre-Declaration {0}", epd917.HEAHEA.RefNumHEA4), EventLogEntryType.Information);
                        else
                            Log(string.Format("G2B error returned for TIR Pre-Declaration {0} : return code {1}", epd917.HEAHEA.RefNumHEA4, result.ReturnCode), EventLogEntryType.Information);
                    }
                }
                else if (epd is EPD014)
                {
                    EPD014 epd014 = (EPD014)epd;

                    Thread.Sleep(10000); // Please write/call your code to validate the structure of the message and to persist it in DB here instead of doing a simple wait
                    bool success = true;

                    EPD009 epd009 = BuildEPD009(epd014, success);
                    string response = Serialize(epd009);
                    Log("Response Content : " + response, EventLogEntryType.Information);
                    TIREPDG2BUploadAck result = SendG2BResponse("TIRPreDeclarationCancellationReply", response);

                    if (result.ReturnCode == (int)AckReturnCode.Success)
                        Log(string.Format("EPD009 transmitted with success for TIR Cancellation Request {0}", epd009.HEAHEA.DocNumHEA5), EventLogEntryType.Information);
                    else
                        Log(string.Format("G2B error returned for TIR Cancellation Request {0} : return code {1}", epd009.HEAHEA.DocNumHEA5, result.ReturnCode), EventLogEntryType.Information);
                }
                else if (epd is EPD013)
                {
                    EPD013 epd013 = (EPD013)epd;

                    Thread.Sleep(10000); // Please write/call your code to validate the structure of the message and to persist it in DB here instead of doing a simple wait
                    bool success = true;

                    if (success)
                    {
                        EPD004 epd004 = BuildEPD004(epd013);
                        string response = Serialize(epd004);
                        Log("Response Content : " + response, EventLogEntryType.Information);
                        TIREPDG2BUploadAck result = SendG2BResponse("TIRPreDeclarationAmendmentAccepted", response);

                        if (result.ReturnCode == (int)AckReturnCode.Success)
                            Log(string.Format("EPD004 transmitted with success for TIR Amendment {0}", epd004.HEAHEA.DocNumHEA5), EventLogEntryType.Information);
                        else
                            Log(string.Format("G2B error returned for TIR Amendment {0} : return code {1}", epd004.HEAHEA.DocNumHEA5, result.ReturnCode), EventLogEntryType.Information);
                    }
                    else
                    {
                        EPD005 epd005 = BuildEPD005(epd013);
                        string response = Serialize(epd005);
                        Log("Response Content : " + response, EventLogEntryType.Information);
                        TIREPDG2BUploadAck result = SendG2BResponse("TIRPreDeclarationAmendmentRejected", response);

                        if (result.ReturnCode == (int)AckReturnCode.Success)
                            Log(string.Format("EPD005 transmitted with success for TIR Amendment {0}", epd005.HEAHEA.DocNumHEA5), EventLogEntryType.Information);
                        else
                            Log(string.Format("G2B error returned for TIR Amendment {0} : return code {1}", epd005.HEAHEA.DocNumHEA5, result.ReturnCode), EventLogEntryType.Information);
                    }
                }
                else if (epd is EPD141)
                {
                    EPD141 epd141 = (EPD141)epd;

                    Thread.Sleep(10000); // Please write/call your code to validate the structure of the message and to persist it in DB here instead of doing a simple wait

                    Log(string.Format("TIR Information on non-arrived movement processed {0}", epd141.HEAHEA.DocNumHEA5), EventLogEntryType.Information);
                }
            }
            catch (Exception ex)
            {
                Log(ex.Message + "\r\n" + ex.StackTrace, EventLogEntryType.Error);
                throw new B2GException("An exception occured: " + ex.Message, AckReturnCode.AnyUnclassifiedError);
            }
        }

        private EPD928 BuildEPD928(EPD015 epd015)
        {
            EPD928 epd928 = new EPD928();
            epd928.HEAHEA = new EPD928HEAHEA();
            epd928.CUSOFFDEPEPT = new CUSOFFDEPEPTType();
            epd928.TRAPRIPC1 = new TRAPRIPC1Type();
            epd928.HEAHEA.RefNumHEA4 = epd015.HEAHEA.RefNumHEA4;
            epd928.CUSOFFDEPEPT.RefNumEPT1 = epd015.CUSOFFDEPEPT.RefNumEPT1;
            epd928.TRAPRIPC1.CitPC124 = epd015.TRAPRIPC1.CitPC124;
            epd928.TRAPRIPC1.CouPC125 = epd015.TRAPRIPC1.CouPC125;
            epd928.TRAPRIPC1.NADLNGPC = epd015.TRAPRIPC1.NADLNGPC;
            epd928.TRAPRIPC1.NamPC17 = epd015.TRAPRIPC1.NamPC17;
            epd928.TRAPRIPC1.PosCodPC123 = epd015.TRAPRIPC1.PosCodPC123;
            epd928.TRAPRIPC1.StrAndNumPC122 = epd015.TRAPRIPC1.StrAndNumPC122;
            epd928.TRAPRIPC1.TINPC159 = epd015.TRAPRIPC1.TINPC159;
            epd928.TRAPRIPC1.HITPC126 = epd015.TRAPRIPC1.HITPC126;
            return epd928;
        }

        private EPD917 BuildEPD917(EPD015 epd015)
        {
            EPD917 epd917 = new EPD917();
            epd917.HEAHEA = new EPD917HEAHEA();
            epd917.FUNERRER1 = new FUNERRER1Type();
            epd917.HEAHEA.RefNumHEA4 = epd015.HEAHEA.RefNumHEA4;
            epd917.FUNERRER1.ErrPoiER12 = "/EPD015/HEAHEA/RefNUMHEA4";
            epd917.FUNERRER1.OriAttValER14 = epd015.HEAHEA.RefNumHEA4;
            epd917.FUNERRER1.ErrTypER11 = "12";
            epd917.FUNERRER1.ErrReaER13 = "Duplicate LRN";
            return epd917;
        }

        private EPD009 BuildEPD009(EPD014 epd014, bool acceptIt)
        {
            EPD009 epd009 = new EPD009();
            epd009.HEAHEA = new EPD009HEAHEA();
            epd009.CUSOFFDEPEPT = new CUSOFFDEPEPTType();
            epd009.TRAPRIPC1 = new TRAPRIPC1Type();
            epd009.HEAHEA.DocNumHEA5 = epd014.HEAHEA.DocNumHEA5;
            epd009.HEAHEA.CanDecHEA93 = acceptIt ? EPD009HEAHEACanDecHEA93.Item1 : EPD009HEAHEACanDecHEA93.Item0;
            epd009.HEAHEA.CanDecHEA93Specified = true;

            if (epd014.HEAHEA.CancellationRequestDateSpecified)
            {
                epd009.HEAHEA.CancellationRequestDateSpecified = true;
                epd009.HEAHEA.CancellationRequestDate = epd014.HEAHEA.CancellationRequestDate;
                epd009.HEAHEA.CancellationDecisionDate = DateTime.Now.Date;
                epd009.HEAHEA.CancellationDecisionDateSpecified = true;
            }

            if (!String.IsNullOrEmpty(epd014.HEAHEA.DatOfCanReqHEA147))
            {
                epd009.HEAHEA.DatOfCanReqHEA147 = epd014.HEAHEA.DatOfCanReqHEA147;
                epd009.HEAHEA.DatOfCanDecHEA146 = DateTime.Now.ToString("yyyyMMdd");
            }

            epd009.CUSOFFDEPEPT.RefNumEPT1 = epd014.CUSOFFDEPEPT.RefNumEPT1;
            epd009.TRAPRIPC1.CitPC124 = epd014.TRAPRIPC1.CitPC124;
            epd009.TRAPRIPC1.CouPC125 = epd014.TRAPRIPC1.CouPC125;
            epd009.TRAPRIPC1.NADLNGPC = epd014.TRAPRIPC1.NADLNGPC;
            epd009.TRAPRIPC1.NamPC17 = epd014.TRAPRIPC1.NamPC17;
            epd009.TRAPRIPC1.PosCodPC123 = epd014.TRAPRIPC1.PosCodPC123;
            epd009.TRAPRIPC1.StrAndNumPC122 = epd014.TRAPRIPC1.StrAndNumPC122;
            epd009.TRAPRIPC1.TINPC159 = epd014.TRAPRIPC1.TINPC159;
            epd009.TRAPRIPC1.HITPC126 = epd014.TRAPRIPC1.HITPC126;
            return epd009;
        }

        private EPD004 BuildEPD004(EPD013 epd013)
        {
            EPD004 epd004 = new EPD004();

            epd004.HEAHEA = new EPD004HEAHEA();
            epd004.HEAHEA.DocNumHEA5 = epd013.HEAHEA.DocNumHEA5;
            epd004.HEAHEA.GuaranteeNumber = epd013.HEAHEA.GuaranteeNumber;

            if (epd013.HEAHEA.AmendmentDateSpecified)
            {
                epd004.HEAHEA.AmendmentDate = epd013.HEAHEA.AmendmentDate;
                epd004.HEAHEA.AmendmentDateSpecified = true;
            }
            epd004.HEAHEA.AmendmentAcceptanceDate = DateTime.UtcNow.Date;
            epd004.HEAHEA.AmendmentAcceptanceDateSpecified = true;

            if (epd013.TRAPRIPC1 != null)
            {
                epd004.TRAPRIPC1 = new TRAPRIPC1Type();
                epd004.TRAPRIPC1.NamPC17 = epd013.TRAPRIPC1.NamPC17;
                epd004.TRAPRIPC1.StrAndNumPC122 = epd013.TRAPRIPC1.StrAndNumPC122;
                epd004.TRAPRIPC1.PosCodPC123 = epd013.TRAPRIPC1.PosCodPC123;
                epd004.TRAPRIPC1.CitPC124 = epd013.TRAPRIPC1.CitPC124;
                epd004.TRAPRIPC1.CouPC125 = epd013.TRAPRIPC1.CouPC125;
                epd004.TRAPRIPC1.NADLNGPC = epd013.TRAPRIPC1.NADLNGPC;
                epd004.TRAPRIPC1.TINPC159 = epd013.TRAPRIPC1.TINPC159;
                epd004.TRAPRIPC1.HITPC126 = epd013.TRAPRIPC1.HITPC126;
                epd004.TRAPRIPC1.TAXPC159 = epd013.TRAPRIPC1.TAXPC159;
            }

            if (epd013.CUSOFFDEPEPT != null)
            {
                epd004.CUSOFFDEPEPT = new CUSOFFDEPEPTType();
                if (!string.IsNullOrEmpty(epd013.CUSOFFDEPEPT.CouRefNumEPT1)) { epd004.CUSOFFDEPEPT.CouRefNumEPT1 = epd013.CUSOFFDEPEPT.CouRefNumEPT1;}
                epd004.CUSOFFDEPEPT.RefNumEPT1 = epd013.CUSOFFDEPEPT.RefNumEPT1;
            }

            return epd004;
        }

        private EPD005 BuildEPD005(EPD013 epd013)
        {
            EPD005 epd005 = new EPD005();
            epd005.HEAHEA = new EPD005HEAHEA();
            epd005.HEAHEA.DocNumHEA5 = epd013.HEAHEA.DocNumHEA5;
            epd005.HEAHEA.GuaranteeNumber = epd013.HEAHEA.GuaranteeNumber;

            if (epd013.HEAHEA.AmendmentDateSpecified)
            {
                epd005.HEAHEA.AmendmentDate = epd013.HEAHEA.AmendmentDate;
                epd005.HEAHEA.AmendmentDateSpecified = true;
            }

            epd005.HEAHEA.AmendmentRejectionDate = DateTime.UtcNow.Date;
            epd005.HEAHEA.AmendmentRejectionDateSpecified = true;

            FUNERRER1Type funerrer1 = new FUNERRER1Type();
            funerrer1.ErrPoiER12 = "EPD013/HEAHEA/DocNumHEA5";
            funerrer1.OriAttValER14 = epd013.HEAHEA.DocNumHEA5;
            funerrer1.ErrTypER11 = "12";
            funerrer1.ErrReaER13 = "MRN has been already use for Transit";
            epd005.FUNERRER1 = new List<FUNERRER1Type>();
            epd005.FUNERRER1.Add(funerrer1);

            if (epd013.TRAPRIPC1 != null)
            {
                epd005.TRAPRIPC1 = new TRAPRIPC1Type();
                epd005.TRAPRIPC1.NamPC17 = epd013.TRAPRIPC1.NamPC17;
                epd005.TRAPRIPC1.StrAndNumPC122 = epd013.TRAPRIPC1.StrAndNumPC122;
                epd005.TRAPRIPC1.PosCodPC123 = epd013.TRAPRIPC1.PosCodPC123;
                epd005.TRAPRIPC1.CitPC124 = epd013.TRAPRIPC1.CitPC124;
                epd005.TRAPRIPC1.CouPC125 = epd013.TRAPRIPC1.CouPC125;
                epd005.TRAPRIPC1.NADLNGPC = epd013.TRAPRIPC1.NADLNGPC;
                epd005.TRAPRIPC1.TINPC159 = epd013.TRAPRIPC1.TINPC159;
                epd005.TRAPRIPC1.HITPC126 = epd013.TRAPRIPC1.HITPC126;
                epd005.TRAPRIPC1.TAXPC159 = epd013.TRAPRIPC1.TAXPC159;
            }

            if (epd013.CUSOFFDEPEPT != null)
            {
                epd005.CUSOFFDEPEPT = new CUSOFFDEPEPTType();

                if (!string.IsNullOrEmpty(epd013.CUSOFFDEPEPT.CouRefNumEPT1))
                    epd005.CUSOFFDEPEPT.CouRefNumEPT1 = epd013.CUSOFFDEPEPT.CouRefNumEPT1;

                epd005.CUSOFFDEPEPT.RefNumEPT1 = epd013.CUSOFFDEPEPT.RefNumEPT1;
            }

            return epd005;
        }

        private TIREPDG2BUploadAck SendG2BResponse(string messageName, string messageContent)
        {
            string G2BUrl = ConfigurationManager.AppSettings["G2BWebServiceURL"];
            string certFile = ConfigurationManager.AppSettings["G2BCertificatePath"];
            X509Certificate2 cert = EncryptionHelper.GetCertificateFromFile(certFile);
            EncryptionResult encryptionResult = EncryptionHelper.X509EncryptString(messageContent, cert);
            BasicHttpBinding binding = new BasicHttpBinding();
            if (G2BUrl.ToLower().StartsWith("https"))
                binding = new BasicHttpBinding(BasicHttpSecurityMode.Transport);
            EndpointAddress remoteAddress = new EndpointAddress(G2BUrl);

            TIREPDG2BServiceClassSoapClient cli = new TIREPDG2BServiceClassSoapClient(binding, remoteAddress);
            TIREPDG2BUploadParams parameters = new TIREPDG2BUploadParams();
            parameters.MessageName = messageName;
            parameters.SubscriberID = ConfigurationManager.AppSettings["SubscriberID"];
            parameters.InformationExchangeVersion = "1.0.0";
            parameters.CertificateID = encryptionResult.Thumbprint;
            parameters.ESessionKey = encryptionResult.SessionKey;
            parameters.MessageContent = encryptionResult.Encrypted;
            parameters.SubscriberMessageID = Guid.NewGuid().ToString();
            parameters.TimeSent = DateTime.Now;
            return cli.TIREPDG2B(parameters);
        }

        private string Serialize(object obj)
        {
            XmlSerializer ser = new XmlSerializer(obj.GetType());
            StringWriter writer = new StringWriter();
            ser.Serialize(writer, obj);
            return writer.ToString();
        }

        private object Deserialize(string messageContent, Type t)
        {
            try
            {
                XmlSerializer ser = new XmlSerializer(t);
                StringReader reader = new StringReader(messageContent);
                return ser.Deserialize(reader);
            }
            catch (Exception ex)
            {
                Log(ex.Message, EventLogEntryType.Error);  
                if (ex.InnerException != null)
                    Log(ex.InnerException.Message, EventLogEntryType.Error);  
                throw new B2GException(AckReturnCode.SchemaValidation, ex);                              
            }
        }
    }
}
