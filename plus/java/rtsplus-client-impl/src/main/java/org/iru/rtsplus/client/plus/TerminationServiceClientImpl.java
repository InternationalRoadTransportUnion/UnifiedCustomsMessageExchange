package org.iru.rtsplus.client.plus;

import java.util.Date;
import java.util.LinkedHashSet;
import java.util.Set;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;

import org.iru.rts.model.termination_1.ReconciliationRequestRepliesType;
import org.iru.rts.model.termination_1.ReconciliationRequestType;
import org.iru.rts.model.termination_1.TIROperationTerminationsType;
import org.iru.rts.services.terminationservice_1.ReconciliationRequestsType;
import org.iru.rts.services.terminationservice_1.TerminationService;
import org.iru.rts.services.terminationservice_1.TerminationServiceSEI;
import org.iru.rts.services.terminationservice_1.TransmitReconciliationRequestReplies;
import org.iru.rtsplus.client.TerminationServiceClient;

import jakarta.xml.ws.Holder;

public class TerminationServiceClientImpl extends AbstractWSSClient implements TerminationServiceClient {

	protected QName getServiceQName() {
		return new QName("http://rts.iru.org/services/TerminationService-1", "TerminationService");
	}
	
	protected QName getPortQName() {
		return new QName("http://rts.iru.org/services/TerminationService-1", "TerminationServicePort"+portNameSuffix);
	}
	
	protected TerminationServiceSEI getWsPort() {
		return getWsPort(TerminationService.class, TerminationServiceSEI.class);
	}

	public void transmitTIROperationTerminations(TIROperationTerminationsType tirOperationTerminations, String transmissionId) throws DatatypeConfigurationException {
		transmitTIROperationTerminations(tirOperationTerminations, transmissionId, new Date());
	}

	@Override
	public void transmitTIROperationTerminations(TIROperationTerminationsType tirOperationTerminations, String transmissionId, Date transmissionTime) throws DatatypeConfigurationException {     
		Holder<XMLGregorianCalendar> transmissionTimeH = new Holder<XMLGregorianCalendar>();
		Holder<Boolean> success = new Holder<Boolean>();
        
		transmissionTimeH.value = convertToXML(transmissionTime);

		TerminationServiceSEI wsPort = getWsPort();
		wsPort.transmitTIROperationTerminations(transmissionTimeH, transmissionId, tirOperationTerminations, success); 
	}

	@Override
	public Set<ReconciliationRequestType> getReconciliationRequests(Date from, Date to, Long retrievalRange) throws DatatypeConfigurationException {
		TerminationServiceSEI wsPort = getWsPort();

		XMLGregorianCalendar xFrom = convertToXML(from); 
		XMLGregorianCalendar xTo = convertToXML(to);

		int offset = 0;

		Set<ReconciliationRequestType> reconciliationRequests = new LinkedHashSet<ReconciliationRequestType>();
		while (true) {
			ReconciliationRequestsType.ReconciliationRequests data = wsPort.getReconciliationRequests(xFrom, xTo, offset, retrievalRange).getReconciliationRequests();
			reconciliationRequests.addAll(data.getReconciliationRequest());
			retrievalRange = (long) data.getCount();
			if (data.isEndReached())
				break;
			else
				offset = data.getOffset()+data.getCount();
		}
		return reconciliationRequests;
	}

	@Override
	public void transmitReconciliationRequestReplies(ReconciliationRequestRepliesType reconciliationRequestReplies, String transmissionId, Date transmissionTime) throws DatatypeConfigurationException {
		TransmitReconciliationRequestReplies parameters = new TransmitReconciliationRequestReplies();
		parameters.setReconciliationRequestReplies(reconciliationRequestReplies);
		parameters.setTransmissionId(transmissionId);
		parameters.setTransmissionTime(convertToXML(transmissionTime));

		TerminationServiceSEI wsPort = getWsPort();
		wsPort.transmitReconciliationRequestReplies(parameters);     
	}

	 
}
