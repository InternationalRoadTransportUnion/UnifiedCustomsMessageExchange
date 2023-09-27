package org.iru.tirepd.ws.g2b.client;

import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.util.GregorianCalendar;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.namespace.QName;

import org.iru.common.crypto.wscrypto.CipheredData;
import org.iru.common.crypto.wscrypto.Encrypter;
import org.iru.rts.ws.tirepd_g2b_1.TIREPDG2BService;
import org.iru.rts.ws.tirepd_g2b_1.TIREPDG2BServiceClassSoap;
import org.iru.rts.ws.tirepd_g2b_1.TIREPDG2BUploadAck;
import org.iru.rts.ws.tirepd_g2b_1.TIREPDG2BUploadParams;

import jakarta.xml.bind.JAXBException;

public class G2BClient {
	
	protected String sender;
	protected URL epdg2bEndpoint;
	
	private byte[] iruCertificate;

	public void setSender(String sender) {
		this.sender = sender;
	}

	public void setIruCertificate(byte[] iruCertificate) throws IOException {
		this.iruCertificate = iruCertificate;
	}

	public void setEPDG2BEndpoint(URL epdg2bEndpoint) {
		this.epdg2bEndpoint = epdg2bEndpoint;
	}
	
	public int upload(String messageID, String messageName, Object payload) throws JAXBException, GeneralSecurityException, DatatypeConfigurationException {
		TIREPDG2BService service = new TIREPDG2BService(epdg2bEndpoint, new QName("http://www.iru.org", "TIREPDG2BService"));
		
		TIREPDG2BServiceClassSoap g2b = service.getTIREPDG2BServiceClassSoap();
		TIREPDG2BUploadParams su = new TIREPDG2BUploadParams();
		su.setSubscriberID(sender);
		su.setSubscriberMessageID(messageID);
		su.setInformationExchangeVersion("1.0.0");
		su.setMessageName(messageName);
		su.setTimeSent(DatatypeFactory.newInstance().newXMLGregorianCalendar(new GregorianCalendar()));
		
		
		Encrypter enc = new Encrypter();
		enc.setCertificate(iruCertificate);
		CipheredData d = enc.cryptPayload(payload);
		su.setESessionKey(d.getSessionKey());
		su.setCertificateID(enc.getCertificateThumbprint());
		su.setMessageContent(d.getPayload());
		
		
		TIREPDG2BUploadAck ack = g2b.tirepdg2B(su);
		return ack.getReturnCode();
	}
	
}
