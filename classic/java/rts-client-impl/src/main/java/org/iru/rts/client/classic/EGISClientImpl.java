package org.iru.rts.client.classic;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.GregorianCalendar;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;

import org.iru.common.crypto.wscrypto.CipheredData;
import org.iru.common.crypto.wscrypto.Decrypter;
import org.iru.common.crypto.wscrypto.Encrypter;
import org.iru.epd.model.message.nons.EPD025;
import org.iru.epd.model.message.nons.EPD029;
import org.iru.epd.model.message.nons.EPD045;
import org.iru.rts.client.EGISClient;
import org.iru.rts.client.EGISResponse;
import org.iru.rts.client.ReturnCode;
import org.iru.rts.client.TIROperationMessages;
import org.iru.rts.egis.EGISQueryType;
import org.iru.rts.egis.EGISResponseType;
import org.iru.rts.egis.ObjectFactory;
import org.iru.rts.egis.QueryBodyType;
import org.iru.rts.safetirupload.Records;
import org.iru.rts.tchq.tchquery.EnvelopeType;
import org.iru.rts.ws.egis_1.EGISClass;
import org.iru.rts.ws.egis_1.EGISClassSoap;

import jakarta.xml.bind.JAXBException;

public class EGISClientImpl extends AbstractQueryClient implements EGISClient {

	@Override
	public EGISResponse queryCarnet(String carnetNumber, String queryID) throws DatatypeConfigurationException,
			IOException, JAXBException, GeneralSecurityException, XMLStreamException {

		QueryBodyType b = new QueryBodyType();
		b.setCarnetNumber(carnetNumber);
		b.setOriginator(sender);
		b.setOriginTime(DatatypeFactory.newInstance().newXMLGregorianCalendar(new GregorianCalendar()));
		b.setPassword(password);
		b.setQueryType(1);
		b.setSender(sender);

		EGISQueryType q = new EGISQueryType();

		b.setSentTime(DatatypeFactory.newInstance().newXMLGregorianCalendar(new GregorianCalendar()));

		q.setBody(b);
		q.setEnvelope(new EnvelopeType());

		Encrypter enc = makeEncrypter();

		CipheredData d = enc.cryptPayload(new ObjectFactory().createEGISQuery(q));

		EGISClassSoap egis = getServicePort();

		org.iru.rts.ws.egis_1.EGISQueryType query = new org.iru.rts.ws.egis_1.EGISQueryType();
		query.setSubscriberID(sender);
		query.setQueryID(queryID);
		query.setMessageTag(enc.getCertificateThumbprint());
		query.setESessionKey(d.getSessionKey());
		query.setEGISQueryParams(d.getPayload());
		org.iru.rts.ws.egis_1.EGISResponseType response = egis.egisQuery(query);

		/*
		 *  
		 */
		ReturnCode rc = ReturnCode.getByCode(response.getReturnCode());
		switch (rc) {
			case INVALID_QUERYID_EXCEPTION:
				throw new IllegalArgumentException("Maximum queryID length exceeded: " + queryID);
			case INVALID_CARNETNUMBER_EXCEPTION:
				throw new IllegalArgumentException("Invalid carnet format: " + carnetNumber);
			default:
				/*
				 * All other return codes will lead to GeneralSecurityException in
				 * getDecrypter()
				 */
				break;
		}

		d = new CipheredData();
		d.setPayload(response.getEGISResponseParams());
		d.setSessionKey(response.getESessionKey());

		Decrypter dec = getDecrypter(response.getMessageTag());

		EGISResponseType dp = (EGISResponseType) dec.decryptPayload(d, EGISResponseType.class);

		EGISResponse result = new EGISResponse();
		result.setResult(dp.getBody().getResult());
		result.setAssociation(dp.getBody().getAssociation());
		result.setCarnetNumber(dp.getBody().getCarnetNumber());
		result.setHolderID(dp.getBody().getHolderID());
		BigInteger numTerminations = dp.getBody().getNumTerminations();
		if (numTerminations != null)
			result.setNumTerminations(numTerminations.intValue());
		XMLGregorianCalendar validityDate = dp.getBody().getValidityDate();
		if (validityDate != null)
			result.setValidityDate(validityDate.toGregorianCalendar());
		result.setVoucherNumber(dp.getBody().getVoucherNumber());
		result.setRequestedGuaranteeNumber(dp.getBody().getRequestedGuaranteeNumber());
		
		TIROperationMessages tirOperationMessages = new TIROperationMessages();
		if (dp.getBody().getTIROperationMessages() != null) {
			tirOperationMessages.setStartMessages(new ArrayList<EPD029>());
			if (dp.getBody().getTIROperationMessages().getStartMessages() != null) {
				tirOperationMessages.getStartMessages().addAll(dp.getBody().getTIROperationMessages().getStartMessages().getEPD029());
			}

			tirOperationMessages.setTerminationAndExitMessages(new ArrayList<Records.Record>());
			if (dp.getBody().getTIROperationMessages().getTerminationAndExitMessages() != null) {
				tirOperationMessages.getTerminationAndExitMessages().addAll(dp.getBody().getTIROperationMessages().getTerminationAndExitMessages().getRecord());
			}

			tirOperationMessages.setDischargeMessages(new ArrayList<EPD045>());
			if (dp.getBody().getTIROperationMessages().getDischargeMessages() != null) {
				tirOperationMessages.getDischargeMessages().addAll(dp.getBody().getTIROperationMessages().getDischargeMessages().getEPD045());
			}

			tirOperationMessages.setUpdateSealsMessages(new ArrayList<EPD025>());
			if (dp.getBody().getTIROperationMessages().getUpdateSealsMessages() != null) {
				tirOperationMessages.getUpdateSealsMessages().addAll(dp.getBody().getTIROperationMessages().getUpdateSealsMessages().getEPD025());
			}
		}
		result.setTIROperationMessages(tirOperationMessages);

		return result;
	}

	protected EGISClassSoap getServicePort() {
		EGISClass service = new EGISClass(rtsEndpoint, new QName("http://rts.iru.org/EGIS", "EGISClass"));
		EGISClassSoap egis = service.getEGISClassSoap();
		putAllBindingProviderRequestContext(egis);
		return egis;
	}

}
