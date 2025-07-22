package org.iru.rts.client.plus;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.Date;
import java.util.List;

import javax.xml.datatype.DatatypeConfigurationException;

import org.iru.model.tir_actor_1.Customs;
import org.iru.rts.client.ReturnCode;
import org.iru.rts.client.UploadClient;
import org.iru.rts.client.plus.converter.WSREConverter;
import org.iru.rts.model.termination_1.ObjectFactory;
import org.iru.rts.model.termination_1.ReconciliationRequestRepliesType;
import org.iru.rts.model.termination_1.ReconciliationRequestReplyType;
import org.iru.rts.model.termination_1.TIROperationTerminationType;
import org.iru.rts.model.termination_1.TIROperationTerminationsType;
import org.iru.rts.safetirupload.CWRType;
import org.iru.rts.safetirupload.PFDType;
import org.iru.rts.safetirupload.Records;
import org.iru.rts.safetirupload.RequestReplyRecords;
import org.iru.rts.safetirupload.TCOType;
import org.iru.rts.safetirupload.UPGType;
import org.iru.rtsplus.client.plus.TerminationServiceClientImpl;

import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;

public class UploadClientImpl extends TerminationServiceClientImpl implements UploadClient {
	
	public ReturnCode wsst(List<Records.Record> safeTIRRecords, String messageID) throws JAXBException, GeneralSecurityException, DatatypeConfigurationException {
		return wsst(safeTIRRecords, messageID, new Date());
	}
	
	@Override
	public ReturnCode wsst(List<Records.Record> safeTIRRecords, String messageID, Date sentTime) throws JAXBException, GeneralSecurityException, DatatypeConfigurationException {
		TIROperationTerminationsType terminations = new TIROperationTerminationsType();
		ObjectFactory of = new ObjectFactory();
		try {
			for (Records.Record safeTIRRecord: safeTIRRecords) {
				TIROperationTerminationType termination = new TIROperationTerminationType();
				termination.setTIRCarnetNumber(safeTIRRecord.getTNO());
				termination.setVoletPageNumber(safeTIRRecord.getVPN() != null && !BigInteger.ZERO.equals(safeTIRRecord.getVPN()) ? safeTIRRecord.getVPN().shortValue() : null);
				Customs customs = new Customs();
				customs.setCountryCode(safeTIRRecord.getICC());
				termination.setCustoms(customs);
				termination.setCustomsOffice(safeTIRRecord.getCOF());
				termination.setCustomsLedgerEntryReference(safeTIRRecord.getCNL());
				termination.setCustomsLedgerEntryDate(safeTIRRecord.getDCL());
				termination.setCertificateOfTerminationReference(safeTIRRecord.getRND());
				termination.setCertificateOfTerminationDate(safeTIRRecord.getDDI());
				termination.setIsFinal(safeTIRRecord.getTCO() != null ? null : PFDType.FD.equals(safeTIRRecord.getPFD()));
				termination.setIsWithReservation(CWRType.R.equals(safeTIRRecord.getCWR()));
				termination.setIsBeforeLoad(TCOType.LOAD.equals(safeTIRRecord.getTCO()) ? true : null);
				termination.setIsExit(TCOType.EXIT.equals(safeTIRRecord.getTCO()) ? true : null);
				termination.setCustomsComment(safeTIRRecord.getCOM());
				termination.setPackageCount(safeTIRRecord.getPIC() != null ? safeTIRRecord.getPIC().longValue() : null);

				JAXBElement<TIROperationTerminationType> t;
				if (safeTIRRecord.getUPG() == null || UPGType.N.equals(safeTIRRecord.getUPG())) {
					t = of.createNewTIROperationTermination(termination);
				} else {
					t = of.createCancelledTIROperationTermination(termination);
				}
				terminations.getNewTIROperationTerminationOrCancelledTIROperationTerminationOrUpdatedTIROperationTermination().add(t);
			}
			terminations.setCount((long) terminations.getNewTIROperationTerminationOrCancelledTIROperationTerminationOrUpdatedTIROperationTermination().size());
			transmitTIROperationTerminations(terminations, messageID, sentTime);
		} catch (Exception e) {
			return ReturnCode.UNCLASSIFIED_ERROR;
		}
		return ReturnCode.SUCCESS;
	}

	@Override
	public ReturnCode wsre(List<RequestReplyRecords.RequestReplyRecord> rrRecords, String messageID) throws JAXBException, GeneralSecurityException, DatatypeConfigurationException {
		ReconciliationRequestRepliesType reconciliationRequestReplies = new ReconciliationRequestRepliesType();
		try {
			for (RequestReplyRecords.RequestReplyRecord rrRecord : rrRecords) {
				ReconciliationRequestReplyType requestReply = new ReconciliationRequestReplyType();
				requestReply.setId(rrRecord.getRequestID());
				requestReply.setReplyType(WSREConverter.convertRequestReplyToReplyType(rrRecord.getRequestReplyType()));
				TIROperationTerminationType termination = new TIROperationTerminationType();
				termination.setTIRCarnetNumber(rrRecord.getTNO());
				termination.setVoletPageNumber(rrRecord.getVPN() != null && !BigInteger.ZERO.equals(rrRecord.getVPN()) ? rrRecord.getVPN().shortValue() : null);
				Customs customs = new Customs();
				customs.setCountryCode(rrRecord.getICC());
				termination.setCustoms(customs);
				termination.setCustomsOffice(rrRecord.getCOF());
				termination.setCustomsLedgerEntryReference(rrRecord.getCNL());
				termination.setCustomsLedgerEntryDate(rrRecord.getDCL());
				termination.setCertificateOfTerminationReference(rrRecord.getRND());
				termination.setCertificateOfTerminationDate(rrRecord.getDDI());
				termination.setIsFinal(rrRecord.getTCO() != null ? null : PFDType.FD.equals(rrRecord.getPFD()));
				termination.setIsWithReservation(CWRType.R.equals(rrRecord.getCWR()));
				termination.setIsBeforeLoad(TCOType.LOAD.equals(rrRecord.getTCO()) ? true : null);
				termination.setIsExit(TCOType.EXIT.equals(rrRecord.getTCO()) ? true : null);
				termination.setCustomsComment(rrRecord.getCOM());
				termination.setPackageCount(rrRecord.getPIC() != null ? rrRecord.getPIC().longValue() : null);
				
				requestReply.setCorrectedTIROperationTermination(termination);
				reconciliationRequestReplies.getReconciliationRequestReply().add(requestReply);
			}
			reconciliationRequestReplies.setCount((long) reconciliationRequestReplies.getReconciliationRequestReply().size());
			transmitReconciliationRequestReplies(reconciliationRequestReplies, messageID, new Date());
		} catch (Exception e) {
			return ReturnCode.UNCLASSIFIED_ERROR;
		}
		return ReturnCode.SUCCESS;
	}
	
}
