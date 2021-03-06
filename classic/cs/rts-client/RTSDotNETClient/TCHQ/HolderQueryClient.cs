﻿using System;
using System.ServiceModel;
using System.Security.Cryptography.X509Certificates;

namespace RTSDotNETClient.TCHQ
{

    /// <summary>
    /// The HolderQueryClient class allows to query the TCHQ Web Service
    /// in order to retrieve some information related to a TIR Carnet (status, holder, association, etc)
    /// </summary>
    public class HolderQueryClient : BaseWSClient
    {
        /// <summary>
        /// The private certificate used for decryption of the response
        /// </summary>
        public X509Certificate2 PrivateCertificate { get; set; }        
        
        /// <summary>
        /// Send a query to the TCHQ Web Service to retrieve some information related to a TIR Carnet (status, holder, association, etc)
        /// </summary>
        /// <param name="query">The query object</param>
        /// <param name="queryId">The query id (optional value the sender may use to track this message)</param>
        /// <returns>The response returned by the TCHQ Web Service</returns>
        public Response QueryCarnet(Query query, string queryId)
        {
            SanityChecks();
            if (this.PrivateCertificate == null)
                throw new Exception("The private certificate is missing.");

            query.CalculateHash();
            string queryStr = query.Serialize();

            Global.Trace("TCHQ QUERY:\r\n" + queryStr + "\r\n");

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
            CarnetHolderQueryWS.SafeTIRHolderQueryServiceClassSoap ws = new CarnetHolderQueryWS.SafeTIRHolderQueryServiceClassSoapClient(binding, remoteAddress);

            CarnetHolderQueryWS.WSTCHQRequest request = new CarnetHolderQueryWS.WSTCHQRequest();
            request.Body = new CarnetHolderQueryWS.WSTCHQRequestBody();
            request.Body.su = new CarnetHolderQueryWS.TIRHolderQuery();
            request.Body.su.SubscriberID = query.Body.Sender;
            request.Body.su.Query_ID = queryId;
            request.Body.su.MessageTag = encrypted.Thumbprint;
            request.Body.su.ESessionKey = encrypted.SessionKey;
            request.Body.su.TIRCarnetHolderQueryParams = encrypted.Encrypted;
            
            CarnetHolderQueryWS.WSTCHQResponse response = ws.WSTCHQ(request);

            // Verify the Return Code => it should be 2 (OK)
            ReturnCode returnCode = (ReturnCode)response.Body.WSTCHQResult.ReturnCode;
            if (returnCode != ReturnCode.SUCCESS)
                throw new RTSWebServiceException(String.Format("{0} ({1})", returnCode.ToString(), (int)returnCode),(int)returnCode);

            string respStr = EncryptionHelper.X509DecryptString(response.Body.WSTCHQResult.ESessionKey,
                    response.Body.WSTCHQResult.TIRCarnetHolderResponseParams, response.Body.WSTCHQResult.MessageTag, this.PrivateCertificate);

            Global.Trace(string.Format("TCHQ RESPONSE: RETURN_CODE={0} ({1})\r\n{2}\r\n", (int)returnCode, returnCode, respStr));

            Response result = QueryResponseFactory.Deserialize<Response>(respStr, Response.Xsd);
            result.RebuildHash(respStr);

            return result;
        }
    }
}
