package org.iru.rts.client;

import java.security.GeneralSecurityException;
import java.util.Date;
import java.util.List;

import jakarta.xml.bind.JAXBException;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.stream.XMLStreamException;

import org.iru.rts.safetirupload.Records;
import org.iru.rts.safetirupload.RequestReplyRecords;

public interface UploadClient {

	public ReturnCode wsst(List<Records.Record> safeTIRRecords, String messageID, Date sentTime) throws JAXBException, GeneralSecurityException, DatatypeConfigurationException, XMLStreamException;
	
	public ReturnCode wsre(List<RequestReplyRecords.RequestReplyRecord> rrRecords, String messageID) throws JAXBException, GeneralSecurityException, DatatypeConfigurationException, XMLStreamException;
	
}
