﻿using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Schema;
using System.Xml.Serialization;
using System.Reflection;
using System.ComponentModel;

namespace RTSDotNETClient.TCHQ
{

    /// <summary>
    /// Type of the query
    /// </summary>
    [Flags]
    public enum QueryType
    {
        /// <summary>
        /// Carnet Holder
        /// </summary>
        [XmlEnum("1")]
        CarnetHolder = 1,

        [XmlEnum("2")]
        CarnetAndVoucher = 2
    }

    /// <summary>
    /// Reason for the query
    /// </summary>
    public enum QueryReason
    {
        /// <summary>
        /// Entry
        /// </summary>
        [XmlEnum("1")]
        Entry = 1,

        /// <summary>
        /// Exit
        /// </summary>
        [XmlEnum("2")]
        Exit = 2,
        
        /// <summary>
        /// Termination
        /// </summary>
        [XmlEnum("3")]
        Termination = 3,
        
        /// <summary>
        /// Opening
        /// </summary>
        [XmlEnum("4")]
        Opening = 4,
        
        /// <summary>
        /// Other
        /// </summary>
        [XmlEnum("5")]
        Other = 5
    }

    /// <summary>
    /// The TIR Carnet Holder Query to be sent to the TCHQ Web Service
    /// </summary>
    [XmlRoot("Query", Namespace = "http://www.iru.org/TCHQuery")]
    public class Query : BaseQueryResponse
    {
        /// <summary>
        /// The xml schema definition file that defines the structure of the query
        /// </summary>
        public const string Xsd = "TCHQuery.xsd";
        
        /// <summary>
        /// The body of the query
        /// </summary>
        public Body<QueryType> Body = new Body<QueryType>();

        /// <summary>
        /// The default constructor
        /// </summary>
        public Query()
        {
            this.xsd = Xsd;
        }        

    }

    /// <summary>
    /// The query body
    /// </summary>
    public class Body<T>
    {
        private QueryReason QueryReasonField;

        /// <summary>
        /// The identification of the sender.
        /// </summary>
        public string Sender{ get; set; }

        /// <summary>
        /// The date and time the query was sent to the WSTCHQ. Time in UTC. See ISO 8601.
        /// </summary>
        public DateTime SentTime{ get; set; }

        /// <summary>
        /// The identification of the customs post which generated the query.
        /// </summary>
        public string Originator{ get; set; }

        /// <summary>
        /// The date and time the Originator created the query. Time in UTC. See ISO 8601.
        /// </summary>
        public DateTime OriginTime{ get; set; }       

        /// <summary>
        /// Password of the sender
        /// </summary>
        public string Password{ get; set; }

        /// <summary>
        /// Type of the query
        /// </summary>
        [XmlElement("Query_Type")]
        public T QueryType{ get; set; }

        [XmlIgnore()]
        [Browsable(false), EditorBrowsable(EditorBrowsableState.Never)]
        public bool QueryReasonSpecified { get; set; }

        /// <summary>
        /// Reason for the query
        /// </summary>
        [XmlElement("Query_Reason")]
        public QueryReason QueryReason
        {
            get
            {
                return QueryReasonField;
            }
            set
            {
                QueryReasonField = value;
                QueryReasonSpecified = true;
            }
        }

        /// <summary>
        /// The Carnet Number
        /// </summary>
        [XmlElement("Carnet_Number")]
        public string CarnetNumber { get; set; }

    }
    
}
