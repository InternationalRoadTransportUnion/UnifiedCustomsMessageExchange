package org.iru.rts.client.classic;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.GregorianCalendar;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;

import org.iru.common.crypto.wscrypto.CipheredData;
import org.iru.common.crypto.wscrypto.Decrypter;
import org.iru.common.crypto.wscrypto.Encrypter;
import org.iru.rts.client.HolderQueryClient;
import org.iru.rts.client.HolderQueryReason;
import org.iru.rts.client.HolderQueryResponse;
import org.iru.rts.client.ReturnCode;
import org.iru.rts.tchq.tchqresponse.QueryResponse;
import org.iru.rts.tchq.tchquery.BodyType;
import org.iru.rts.tchq.tchquery.EnvelopeType;
import org.iru.rts.tchq.tchquery.Query;
import org.iru.rts.ws.tchq_1.SafeTIRHolderQueryServiceClass;
import org.iru.rts.ws.tchq_1.SafeTIRHolderQueryServiceClassSoap;
import org.iru.rts.ws.tchq_1.TIRHolderQuery;
import org.iru.rts.ws.tchq_1.TIRHolderResponse;

import jakarta.xml.bind.JAXBException;

public class HolderQueryClientImpl extends AbstractQueryClient implements HolderQueryClient {

	public HolderQueryResponse queryCarnet(String carnetNumber, String queryID)
			throws DatatypeConfigurationException, IOException, JAXBException, GeneralSecurityException,
			XMLStreamException {
		return queryCarnet(carnetNumber, queryID, HolderQueryReason.OTHER);
	}

	@Override
	public HolderQueryResponse queryCarnet(String carnetNumber, String queryID, HolderQueryReason reason)
			throws DatatypeConfigurationException, IOException, JAXBException, GeneralSecurityException,
			XMLStreamException {
			
		BodyType b = new BodyType();
		b.setCarnetNumber(carnetNumber);
		b.setOriginator(sender);
		b.setOriginTime(DatatypeFactory.newInstance().newXMLGregorianCalendar(new GregorianCalendar()));
		b.setPassword(password);
		b.setQueryReason(reason.codeValue());
		b.setQueryType(1);
		b.setSender(sender);

		Query q = new Query();
		
		b.setSentTime(DatatypeFactory.newInstance().newXMLGregorianCalendar(new GregorianCalendar()));

		q.setBody(b);
		q.setEnvelope(new EnvelopeType());
		
		Encrypter enc = makeEncrypter();

		CipheredData d = enc.cryptPayload(q);
		
		SafeTIRHolderQueryServiceClassSoap tchq = getServicePort();
		
		TIRHolderQuery query = new TIRHolderQuery();
		query.setSubscriberID(sender);
		query.setQueryID(queryID);
		query.setMessageTag(enc.getCertificateThumbprint());
		query.setESessionKey(d.getSessionKey());
		query.setTIRCarnetHolderQueryParams(d.getPayload());
		TIRHolderResponse response = tchq.wstchq(query);
		
		/*
		 *  
		 */
		ReturnCode rc = ReturnCode.getByCode(response.getReturnCode());
		switch (rc) {
		case INVALID_QUERYID_EXCEPTION:
			throw new IllegalArgumentException("Maximum queryID length exceeded: "+queryID);
		case INVALID_CARNETNUMBER_EXCEPTION:
			throw new IllegalArgumentException("Invalid carnet format: "+carnetNumber);
		default:
			/* All other return codes will lead to GeneralSecurityException in getDecrypter() */			
			break;
		}
		
		d = new CipheredData();
		d.setPayload(response.getTIRCarnetHolderResponseParams());
		d.setSessionKey(response.getESessionKey());
		
		Decrypter dec = getDecrypter(response.getMessageTag());
		
		QueryResponse qr = (QueryResponse) dec.decryptPayload(d, QueryResponse.class);
		
		HolderQueryResponse result = new HolderQueryResponse();
		result.setResult(qr.getBody().getResult());
		result.setAssociation(qr.getBody().getAssociation());
		result.setCarnetNumber(qr.getBody().getCarnetNumber());
		result.setHolderID(qr.getBody().getHolderID());
		BigInteger numTerminations = qr.getBody().getNumTerminations();
		if (numTerminations != null)
			result.setNumTerminations(numTerminations.intValue());
		XMLGregorianCalendar validityDate = qr.getBody().getValidityDate();
		if (validityDate != null)
			result.setValidityDate(validityDate.toGregorianCalendar());
		
		return result;
	}

	protected SafeTIRHolderQueryServiceClassSoap getServicePort() {
		SafeTIRHolderQueryServiceClass service = new SafeTIRHolderQueryServiceClass(rtsEndpoint, new QName("http://www.iru.org", "SafeTIRHolderQueryServiceClass"));
		SafeTIRHolderQueryServiceClassSoap tchq = service.getSafeTIRHolderQueryServiceClassSoap();
		putAllBindingProviderRequestContext(tchq);
		return tchq;
	}
	
}
