package org.iru.rts.client.classic;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.GregorianCalendar;
import java.util.List;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;

import org.iru.common.crypto.wscrypto.CipheredData;
import org.iru.common.crypto.wscrypto.Decrypter;
import org.iru.common.crypto.wscrypto.Encrypter;
import org.iru.rts.client.ReconciliationClient;
import org.iru.rts.client.ReturnCode;
import org.iru.rts.safetirreconciliation.EnvelopeType;
import org.iru.rts.safetirreconciliation.ReconciliationQuery;
import org.iru.rts.safetirreconciliation.ReconciliationQueryBodyType;
import org.iru.rts.safetirreconciliation.RequestRecord;
import org.iru.rts.safetirreconciliation.SafeTIR;
import org.iru.rts.ws.wsrq_1.ReconciliationQueryServiceClass;
import org.iru.rts.ws.wsrq_1.ReconciliationQueryServiceClassSoap;
import org.iru.rts.ws.wsrq_1.ReconciliationResponse;

import jakarta.xml.bind.JAXBException;

public class ReconciliationClientImpl extends AbstractQueryClient implements ReconciliationClient {

	private static final String INFORMATION_EXCHANGE_VERSION = "1.0.0";

	public List<RequestRecord> downloadReconciliationRequests(String senderMessageID) throws JAXBException,
			GeneralSecurityException, IOException, DatatypeConfigurationException, XMLStreamException {
		
		ReconciliationQueryBodyType body = new ReconciliationQueryBodyType();
		body.setPassword(password);
		body.setQueryType(1);
		body.setSentTime(DatatypeFactory.newInstance().newXMLGregorianCalendar(new GregorianCalendar()));
		
		ReconciliationQuery q = new ReconciliationQuery();
		q.setBody(body);
		q.setEnvelope(new EnvelopeType());
		q.setSenderDocumentVersion("1.0.0");
		
		Encrypter enc = makeEncrypter();

		CipheredData d = enc.cryptPayload(q);
		
		ReconciliationQueryServiceClassSoap wsrq = getServicePort();
		
		org.iru.rts.ws.wsrq_1.ReconciliationQuery query = new org.iru.rts.ws.wsrq_1.ReconciliationQuery();
		query.setSubscriberID(sender);
		query.setSenderMessageID(senderMessageID);
		query.setMessageTag(enc.getCertificateThumbprint());
		query.setESessionKey(d.getSessionKey());
		query.setReconciliationQueryData(d.getPayload());
		
		query.setInformationExchangeVersion(INFORMATION_EXCHANGE_VERSION);
		
		ReconciliationResponse response = wsrq.wsrq(query);
		
		ReturnCode rc = ReturnCode.getByCode(response.getReturnCode());
		if (rc != ReturnCode.SUCCESS) // FIXME: needs better Exception handling
			throw new RuntimeException(rc.name());
		
		d = new CipheredData();
		d.setPayload(response.getReconciliationRequestData());
		d.setSessionKey(response.getESessionKey());
		
		Decrypter dec = getDecrypter(response.getMessageTag());
		
		SafeTIR qr = (SafeTIR) dec.decryptPayload(d, SafeTIR.class);

		int count = qr.getBody().getNumberOfRecords();
		
		List<RequestRecord> requests = qr.getBody().getRequestRecords().getRequestRecord();
		
		if (count != requests.size())
			throw new IOException("Mismatch count");
		
		return requests;
		
	}

	protected ReconciliationQueryServiceClassSoap getServicePort() {
		ReconciliationQueryServiceClass service = new ReconciliationQueryServiceClass(rtsEndpoint, new QName("http://www.iru.org", "ReconciliationQueryServiceClass"));
		ReconciliationQueryServiceClassSoap wsrq = service.getReconciliationQueryServiceClassSoap();
		putAllBindingProviderRequestContext(wsrq);
		return wsrq;
	}
	
}
