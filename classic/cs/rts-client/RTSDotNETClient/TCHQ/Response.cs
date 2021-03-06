﻿using System;
using System.Xml;
using System.Xml.Serialization;

namespace RTSDotNETClient.TCHQ
{

    /// <summary>
    /// The status of the carnet
    /// </summary>
    public enum ResponseResult
    {
        /// <summary>
        /// Issue Data Available
        /// </summary>
        [XmlEnum("1")]
        IssueDataAvailable = 1,

        /// <summary>
        /// No Issue Data Available
        /// </summary>
        [XmlEnum("2")]
        NoIssueDataAvailable = 2,

        /// <summary>
        /// Carnet has been invalidated by the IRU
        /// </summary>
        [XmlEnum("3")]
        CarnetHasBeenInvalidatedByTheIRU = 3,

        /// <summary>
        /// Carnet is not in circulation
        /// </summary>
        [XmlEnum("4")]
        CarnetIsNotInCirculation = 4,

        /// <summary>
        /// Carnet number is incorrect
        /// </summary>
        [XmlEnum("5")]
        CarnetNumberIsIncorrect = 5
    }

    /// <summary>
    /// The response returned by the TCHQ Web Service
    /// </summary>
    [XmlRoot("QueryResponse", Namespace = "http://www.iru.org/TCHQResponse")]
    public class Response : BaseQueryResponse
    {                
        /// <summary>
        /// The xml schema definition file that defines the structure of the response
        /// </summary>
        public const string Xsd = "TCHQResponse.xsd";

        /// <summary>
        /// The response body
        /// </summary>
        public ResponseBody Body = new ResponseBody();

        /// <summary>
        /// The default constructor
        /// </summary>
        public Response()
        {
            this.xsd = Xsd;
        }
    }

    /// <summary>
    /// The response body
    /// </summary>
    public class ResponseBody
    {
        /// <summary>
        /// The identification of the sender
        /// </summary>
        [XmlElement(Namespace = "http://www.iru.org/TCHQResponse")]
        public string Sender{ get; set; }

        /// <summary>
        /// The identification of the customs post which generated the query.
        /// </summary>
        [XmlElement(Namespace = "http://www.iru.org/TCHQResponse")]
        public string Originator{ get; set; }

        /// <summary>
        /// The date and time the Response was sent. Time in UTC. See ISO 8601.
        /// </summary>
        [XmlElement(Namespace = "http://www.iru.org/TCHQResponse")]
        public DateTime ResponseTime{ get; set; } 
       
        /// <summary>
        /// Only used where Return Code = 2, otherwise blank.
        /// <remarks>2 means that although the association has not informed the IRU that the carnet has been issued, other factors make it seem possible.
        /// 5 means that the carnet number is not syntactically correct.</remarks>
        /// </summary>
        [XmlElement(Namespace = "http://www.iru.org/TCHQResponse")]
        public ResponseResult Result{ get; set; } 
       
        /// <summary>
        /// The carnet number in the query.
        /// </summary>
        [XmlElement("Carnet_Number", Namespace = "http://www.iru.org/TCHQResponse")]
        public string CarnetNumber { get; set; }

        /// <summary>
        /// The holder ID. Only for Result = 1
        /// </summary>
        [XmlElement(Namespace = "http://www.iru.org/TCHQResponse")]
        public string HolderID { get; set; }

        [System.Xml.Serialization.XmlIgnoreAttribute()]
        public bool ValidityDateSpecified;

        /// <summary>
        /// The validity date. Only for Result = 1
        /// </summary>
        [XmlElement(Namespace = "http://www.iru.org/TCHQResponse")]
        public DateTime ValidityDate { get; set; }

        /// <summary>
        /// The short name of the association. This is the association to which the IRU issued the carnet. Only for Result = 1, 2.
        /// </summary>
        [XmlElement(Namespace = "http://www.iru.org/TCHQResponse")]
        public string Association { get; set; }

        /// <summary>
        /// The number of termination (SafeTIR) records for this carnet. Only for Result = 1, 2.
        /// </summary>
        [XmlElement(Namespace = "http://www.iru.org/TCHQResponse")]
        public int NumTerminations { get; set; }

        /// <summary>
        /// The Voucher Number of TIR Plus additional guarantee which is associated to the TIR carnet.
        /// <remarks>It can be null and it is returned only if Query_Type argument of the query has the flag 2.</remarks>
        /// </summary>
        [XmlElement("Voucher_Number", Namespace = "http://www.iru.org/TCHQResponse")]
        public string VoucherNumber { get; set; }
    }
    
}
