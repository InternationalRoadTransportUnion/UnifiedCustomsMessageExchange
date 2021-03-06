﻿using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;

namespace RTSDotNETClient.WSRQ
{
    /// <summary>
    /// The ReconciliationClient class allows to download from IRU the reconciliation requests 
    /// </summary>
    public class ReconciliationClient : BaseWSClient
    {
        private const String InformationExchangeVersion = "1.0.0";

        /// <summary>
        /// The private certificate used for decryption of the response
        /// </summary>
        public X509Certificate2 PrivateCertificate { get; set; }   

        /// <summary>
        /// Download the reconciliation requests from IRU
        /// </summary>
        /// <param name="query">The query object</param>
        /// <param name="subscriberID">The subscriber ID</param>        
        /// <param name="messageId">The message id (required element allowing the IRU to report message processing failures back to the sender)</param>
        /// <returns>Returns a response object</returns>
        public Response DownloadReconciliationRequests(Query query, string subscriberID, string messageId)
        {
            SanityChecks();
            if (this.PrivateCertificate == null)
                throw new Exception("The private certificate is missing.");

            query.CalculateHash();
            string queryStr = query.Serialize();

            Global.Trace("WSRQ QUERY:\r\n" + queryStr + "\r\n");

            // Encryption
            EncryptionResult encrypted = EncryptionHelper.X509EncryptString(queryStr, this.PublicCertificate);

            BasicHttpBinding binding = new BasicHttpBinding();
            binding.ReaderQuotas.MaxArrayLength = int.MaxValue;
            binding.ReaderQuotas.MaxBytesPerRead = int.MaxValue;
            binding.ReaderQuotas.MaxDepth = int.MaxValue;
            binding.ReaderQuotas.MaxNameTableCharCount = int.MaxValue;
            binding.ReaderQuotas.MaxStringContentLength = int.MaxValue;
            binding.MaxBufferSize = int.MaxValue;
            binding.MaxReceivedMessageSize = int.MaxValue;
            binding.OpenTimeout = TimeSpan.FromMinutes(3.0);
            binding.SendTimeout = TimeSpan.FromMinutes(5.0);
            binding.ReceiveTimeout = TimeSpan.FromMinutes(5.0);
            binding.CloseTimeout = TimeSpan.FromMinutes(3.0);
            EndpointAddress remoteAddress = new EndpointAddress(this.WebServiceUrl);
            switch (remoteAddress.Uri.Scheme)
            {
                case "http":
                    binding.Security.Mode = BasicHttpSecurityMode.None;
                    break;
                case "https":
                    binding.Security.Mode = BasicHttpSecurityMode.Transport;
                    break;
                default:
                    binding.Security.Mode = BasicHttpSecurityMode.None;
                    break;
            }

            // Call the Web Service
            ReconciliationWS.ReconciliationQueryServiceClassSoap ws = new ReconciliationWS.ReconciliationQueryServiceClassSoapClient(binding, remoteAddress);
            
            ReconciliationWS.WSRQRequest request = new ReconciliationWS.WSRQRequest();
            request.Body = new ReconciliationWS.WSRQRequestBody();
            request.Body.su = new ReconciliationWS.ReconciliationQuery();
            request.Body.su.SubscriberID = subscriberID;
            request.Body.su.Sender_MessageID = messageId;
            request.Body.su.MessageTag = encrypted.Thumbprint;
            request.Body.su.ESessionKey = encrypted.SessionKey;
            request.Body.su.ReconciliationQueryData = encrypted.Encrypted;
            request.Body.su.Information_Exchange_Version = InformationExchangeVersion;

            ReconciliationWS.WSRQResponse response = ws.WSRQ(request);

            // Verify the Return Code => it should be 2 (OK)
            ReturnCode returnCode = (ReturnCode)response.Body.WSRQResult.ReturnCode;
            if (returnCode != ReturnCode.SUCCESS)
                throw new RTSWebServiceException(String.Format("{0} ({1})", returnCode.ToString(), (int)returnCode), (int)returnCode);

            string respStr = EncryptionHelper.X509DecryptString(response.Body.WSRQResult.ESessionKey,
                    response.Body.WSRQResult.ReconciliationRequestData, response.Body.WSRQResult.MessageTag, this.PrivateCertificate);

            Global.Trace(string.Format("WSRQ RESPONSE: RETURN_CODE={0} ({1})\r\n{2}\r\n", (int)returnCode, returnCode, respStr));

            respStr = respStr.Replace(" DDI=\"\"", "");

            Response result = QueryResponseFactory.Deserialize<Response>(respStr, Response.Xsd);
            result.RebuildHash(respStr);

            return result;
        }
    }
}
