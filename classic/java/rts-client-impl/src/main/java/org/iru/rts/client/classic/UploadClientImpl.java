package org.iru.rts.client.classic;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.namespace.QName;

import org.iru.common.crypto.wscrypto.CipheredData;
import org.iru.common.crypto.wscrypto.Encrypter;
import org.iru.rts.client.ReturnCode;
import org.iru.rts.client.UploadClient;
import org.iru.rts.safetirupload.BodyType;
import org.iru.rts.safetirupload.EnvelopeType;
import org.iru.rts.safetirupload.Records;
import org.iru.rts.safetirupload.RequestReplyRecords;
import org.iru.rts.safetirupload.SafeTIR;
import org.iru.rts.ws.wsst_1.SafeTIRReconParams;
import org.iru.rts.ws.wsst_1.SafeTIRUploadAck;
import org.iru.rts.ws.wsst_1.SafeTIRUploadParams;
import org.iru.rts.ws.wsst_1.SafeTirUpload;
import org.iru.rts.ws.wsst_1.SafeTirUploadSoap;

import jakarta.xml.bind.JAXBException;

public class UploadClientImpl extends AbstractClient implements UploadClient {

	private static final String INFORMATION_EXCHANGE_VERSION = "2.0.0";

	protected SafeTirUploadSoap getServicePort() {
		SafeTirUpload service = new SafeTirUpload(rtsEndpoint, new QName("http://www.iru.org", "SafeTirUpload"));
		SafeTirUploadSoap stus = service.getSafeTirUploadSoap();
		putAllBindingProviderRequestContext(stus);
		return stus;
	}



	private SafeTIR makeWsstSafeTIR(List<Records.Record> safeTIRRecords, String messageID, Date sentTime) throws DatatypeConfigurationException {
		BodyType b = new BodyType();
		b.setPassword(password);
		
		Records r = new Records();
		r.getRecord().addAll(safeTIRRecords);
		b.setSafeTIRRecords(r);
		
		GregorianCalendar cal = new GregorianCalendar();
		cal.setTime(sentTime);
		b.setSentTime(DatatypeFactory.newInstance().newXMLGregorianCalendar(cal));
		b.setSenderMessageID(messageID);
		b.setSubscriberID(sender);
		b.setTCN(BigInteger.valueOf(safeTIRRecords.size()));
		b.setUploadType(1);
		b.setVersion("1.0");
		
		SafeTIR st = new SafeTIR();
		
		st.setBody(b);
		st.setEnvelope(new EnvelopeType());
		return st;
	}
	
	public ReturnCode wsst(List<Records.Record> safeTIRRecords, String messageID) throws JAXBException, GeneralSecurityException, DatatypeConfigurationException {
		return wsst(safeTIRRecords, messageID, new Date());
	}
	
	@Override
	public ReturnCode wsst(List<Records.Record> safeTIRRecords, String messageID, Date sentTime) throws JAXBException, GeneralSecurityException, DatatypeConfigurationException {
		
		SafeTIR st = makeWsstSafeTIR(safeTIRRecords, messageID, sentTime);
		
		Encrypter enc = makeEncrypter();
		CipheredData d = enc.cryptPayload(st);
		
		SafeTirUploadSoap stus = getServicePort();
		
		SafeTIRUploadParams params = new SafeTIRUploadParams();
		params.setSubscriberID(sender);
		params.setSenderMessageID(messageID);
		params.setMessageTag(enc.getCertificateThumbprint());
		params.setESessionKey(d.getSessionKey());
		params.setSafeTIRUploadData(d.getPayload());
		SafeTIRUploadAck ack = stus.wsst(params);
		
		return ReturnCode.getByCode(ack.getReturnCode());
	}

	private SafeTIR makeWsreSafeTIR(List<RequestReplyRecords.RequestReplyRecord> rrRecords, String messageID) throws DatatypeConfigurationException {
		BodyType b = new BodyType();
		
		RequestReplyRecords r = new RequestReplyRecords();
		r.getRequestReplyRecord().addAll(rrRecords);
		b.setRequestReplyRecords(r);
		
		b.setNumberOfRecords(rrRecords.size());
		SafeTIR st = new SafeTIR();
		
		st.setBody(b);
		st.setEnvelope(new EnvelopeType());
		return st;
	}
	
	@Override
	public ReturnCode wsre(List<RequestReplyRecords.RequestReplyRecord> rrRecords, String messageID) throws JAXBException, GeneralSecurityException, DatatypeConfigurationException {
	
		SafeTIR st = makeWsreSafeTIR(rrRecords, messageID);
		
		Encrypter enc = makeEncrypter();
		CipheredData d = enc.cryptPayload(st);
		
		SafeTirUploadSoap stus = getServicePort();
		
		SafeTIRReconParams params = new SafeTIRReconParams();
		params.setSubscriberID(sender);
		params.setSenderMessageID(messageID);
		params.setMessageTag(enc.getCertificateThumbprint());
		params.setESessionKey(d.getSessionKey());
		params.setSafeTIRReconData(d.getPayload());
		params.setInformationExchangeVersion(INFORMATION_EXCHANGE_VERSION);
		
		SafeTIRUploadAck ack = stus.wsre(params);
		return ReturnCode.getByCode(ack.getReturnCode());
	}
	
}
