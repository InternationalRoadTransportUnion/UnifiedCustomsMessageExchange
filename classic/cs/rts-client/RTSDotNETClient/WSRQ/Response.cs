﻿using System;
using System.Collections.Generic;
using System.Xml.Serialization;
using System.ComponentModel;

namespace RTSDotNETClient.WSRQ
{
    /// <summary>
    /// Identifies whether the data is from a customs SafeTIR termination record or from the Souche.
    /// </summary>
    public enum RequestDataSource
    {
        /// <summary>
        /// SafeTIR transmission
        /// </summary>
        [XmlEnum("1")]
        SafeTIRTransmission=1,

        /// <summary>
        /// TIR Carnet
        /// </summary>
        [XmlEnum("2")]
        TirCarnet=2
    }

    /// <summary>
    /// The response object returned by the WSRQ web service
    /// </summary>
    [XmlRoot("SafeTIR", Namespace = "http://www.iru.org/SafeTIRReconciliation")]
    public class Response : BaseQueryResponse
    {
        /// <summary>
        /// The xml schema definition file that defines the structure of the response
        /// </summary>
        public const string Xsd = "SafeTIRReconciliation.xsd";

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
        /// Total Number of Reconciliation Request records sent in this message
        /// </summary>
        public int NumberOfRecords { get; set; }

        /// <summary>
        /// The set of Reconciliation Request Records Uploaded
        /// </summary>
        public List<RequestRecord> RequestRecords { get; set; }
    }

    /// <summary>
    /// One Reconciliation Request Record
    /// </summary>
    public class RequestRecord
    {
        /// <summary>
        /// Unique identifier generated by the IRU.
        /// </summary>
        [XmlAttribute("RequestID")]
        public string RequestID {get;set;}

        /// <summary>
        /// The date and time the IRU first made this request available to the Customs Authorities
        /// </summary>
        [XmlAttribute("RequestDate")]
        public DateTime RequestDate {get;set;}

        /// <summary>
        /// The number of this reminder. Initially is zero. First reminder is 1, second is 2, etc.
        /// </summary>
        [XmlAttribute("RequestReminderNum")]
        public int  RequestReminderNum {get;set;}

        /// <summary>
        /// Identifies whether the data is from a customs SafeTIR termination record or from the Souche.
        /// </summary>
        [XmlAttribute("RequestDataSource")]
        public int RequestDataSource{get;set;}

        /// <summary>
        /// TIR Carnet Reference Number
        /// </summary>
        [XmlAttribute("TNO")]
        public string TNO { get; set; }

        /// <summary>
        /// ISO3 code of the country of termination
        /// </summary>
        [XmlAttribute("ICC")]
        public string ICC { get; set; }

        /// <summary>
        /// Date in Customs Ledger (Termination)
        /// </summary>
        [XmlAttribute("DCL")]
        public DateTime DCL { get; set; }

        /// <summary>
        /// Record Number in Customs Ledger (Termination)
        /// </summary>
        [XmlAttribute("CNL")]
        public string CNL { get; set; }

        /// <summary>
        /// Name or Number of Customs Office
        /// </summary>
        [XmlAttribute("COF")]
        public string COF { get; set; }

        /// <summary>
        /// Date of Discharge
        /// </summary>
        [XmlAttribute("DDI")]
        public DateTime DDI { get; set; }

        /// <summary>
        /// Reference Number of Discharge
        /// </summary>
        [XmlAttribute("RND")]
        public string RND { get; set; }

        /// <summary>
        /// Partial/Final Discharge
        /// </summary>
        [XmlAttribute("PFD")]
        public string PFD { get; set; }

        /// <summary>
        /// Tells to the XML Serializer if <seealso cref="TCO"/> has to be serialized
        /// </summary>
        [Browsable(false), EditorBrowsable(EditorBrowsableState.Never)]
        [System.Xml.Serialization.XmlIgnoreAttribute()]
        public bool TCOSpecified
        {
            get
            {
                return (this.TCO != TCO.NotSpecified);
            }
            set
            {
                if (!value)
                {
                    this.TCO = TCO.NotSpecified;
                }
            }
        }

        /// <summary>
        /// TIR Carnet Operation (optional). It will be LOAD for SafeTIR before load messages (eTIR) and EXIT for SafeTIR exit messages (eTIR)
        /// </summary>
        [XmlAttribute("TCO")]
        public TCO TCO { get; set; }

        /// <summary>
        /// Discharge with or without Reservation. (If Discharge is without reservation, the string "OK" will be used; if with Reserva-tion, one character string, "R", will be used.)
        /// </summary>
        [XmlAttribute("CWR")]
        public CWR CWR {get;set;}

        /// <summary>
        /// Volet Page Number. This field contains the page number of the volet pertaining to the discharge and must be an even number in the range 2 to 20 (inclusive).
        /// </summary>
        [XmlAttribute("VPN")]
        public int VPN { get; set; }

        /// <summary>
        /// A comment
        /// </summary>
        [XmlAttribute("COM")]
        public string COM { get; set; }

        /// <summary>
        /// Tells to the XML Serializer if <seealso cref="RBC"/> has to be serialized
        /// </summary>
        [Browsable(false), EditorBrowsable(EditorBrowsableState.Never)]
        [System.Xml.Serialization.XmlIgnoreAttribute()]
        public bool RBCSpecified
        {
            get
            {
                return (this.RBC != RBC.NotSpecified);
            }
            set
            {
                if (!value)
                {
                    this.RBC = RBC.NotSpecified;
                }
            }
        }

        /// <summary>
        /// Carnet or volet retained by customs or not
        /// </summary>
        [XmlAttribute("RBC")]
        public RBC RBC { get; set; }

        /// <summary>
        /// Number of packages unloaded
        /// </summary>
        [XmlAttribute("PIC")]
        public int PIC { get; set; }

        /// <summary>
        /// Optional remark from the Requestor.
        /// </summary>
        [XmlAttribute("RequestRemark")]
        public string RequestRemark { get; set; }
    }
}
