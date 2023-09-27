package org.iru.rts.client.plus;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.xml.datatype.DatatypeConfigurationException;

import org.iru.rts.client.ReconciliationClient;
import org.iru.rts.client.plus.converter.WSRQConverter;
import org.iru.rts.model.termination_1.MissingTIROperationTerminationType;
import org.iru.rts.model.termination_1.ReconciliationRequestType;
import org.iru.rts.model.termination_1.TIROperationTerminationType;
import org.iru.rts.safetirreconciliation.CWRType;
import org.iru.rts.safetirreconciliation.PFDType;
import org.iru.rts.safetirreconciliation.RequestRecord;
import org.iru.rts.safetirreconciliation.TCOType;
import org.iru.rtsplus.client.plus.TerminationServiceClientImpl;

import jakarta.xml.bind.JAXBException;

public class ReconciliationClientImpl extends TerminationServiceClientImpl implements ReconciliationClient {

	@Override
	public List<RequestRecord> downloadReconciliationRequests(String senderMessageID) throws JAXBException, GeneralSecurityException, IOException, DatatypeConfigurationException {	
		Set<ReconciliationRequestType> requests = getReconciliationRequests(null, null, null);
		
		List<RequestRecord> records = new ArrayList<RequestRecord>(requests.size());
		for (ReconciliationRequestType request : requests) {
			RequestRecord record = new RequestRecord();
			record.setRequestID(request.getId());
			record.setRequestDate(request.getDate());
			record.setRequestReminderNum((int) request.getReminderCount());
			record.setRequestDataSource(WSRQConverter.convertReasonToRequestDataSource(request.getReason()));
	
			record.setRequestRemark(request.getRemark());
			switch (request.getReason()) {
			case MISSING:
				{
					MissingTIROperationTerminationType termination = request.getMissingTIROperationTermination();
					record.setTNO(termination.getTIRCarnetNumber());
					record.setICC(termination.getCustoms().getCountryCode());
					record.setVPN(termination.getVoletPageNumber() != null ? BigInteger.valueOf(termination.getVoletPageNumber()) : BigInteger.ZERO);
					record.setCNL(termination.getCustomsLedgerEntryReference());
					record.setCOF(termination.getCustomsOffice());
					record.setDDI(termination.getCertificateOfTerminationDate());
					record.setRND(termination.getCertificateOfTerminationReference());					
					// TODO?: re-append the termination.getSequenceNumber() to PFD
					record.setPFD(Boolean.TRUE.equals(termination.isIsBeforeLoad()) || Boolean.TRUE.equals(termination.isIsExit()) ? null : Boolean.TRUE.equals(termination.isIsFinal()) ? PFDType.FD : PFDType.PD);
					if (termination.isIsWithReservation() != null)
						record.setCWR(termination.isIsWithReservation() ? CWRType.R : CWRType.OK);
					record.setTCO(Boolean.TRUE.equals(termination.isIsBeforeLoad()) ? TCOType.LOAD : Boolean.TRUE.equals(termination.isIsExit()) ? TCOType.EXIT : null);
					record.setVPN(termination.getVoletPageNumber() != null ? BigInteger.valueOf(termination.getVoletPageNumber()) : BigInteger.ZERO);
					record.setCOM(termination.getCustomsComment());
					record.setPIC(termination.getPackageCount() != null ? BigInteger.valueOf(termination.getPackageCount()) : null);
				}
				break;
			case DISCREPANCY:
				{
					TIROperationTerminationType termination = request.getTIROperationTerminationToValidate();
					record.setTNO(termination.getTIRCarnetNumber());
					record.setICC(termination.getCustoms().getCountryCode());
					record.setDCL(termination.getCustomsLedgerEntryDate());
					record.setCNL(termination.getCustomsLedgerEntryReference());
					record.setCOF(termination.getCustomsOffice());
					record.setDDI(termination.getCertificateOfTerminationDate());
					record.setRND(termination.getCertificateOfTerminationReference());					
					// TODO?: re-append the termination.getSequenceNumber() to PFD
					record.setPFD(Boolean.TRUE.equals(termination.isIsBeforeLoad()) || Boolean.TRUE.equals(termination.isIsExit()) ? null : Boolean.TRUE.equals(termination.isIsFinal()) ? PFDType.FD : PFDType.PD);
					record.setCWR(termination.isIsWithReservation() ? CWRType.R : CWRType.OK);
					record.setTCO(Boolean.TRUE.equals(termination.isIsBeforeLoad()) ? TCOType.LOAD : Boolean.TRUE.equals(termination.isIsExit()) ? TCOType.EXIT : null);
					record.setVPN(termination.getVoletPageNumber() != null ? BigInteger.valueOf(termination.getVoletPageNumber()) : BigInteger.ZERO);
					record.setCOM(termination.getCustomsComment());
					record.setPIC(termination.getPackageCount() != null ? BigInteger.valueOf(termination.getPackageCount()) : null);
				}
				break;
			}
			records.add(record);
		}
		
		return records;
	}

}
