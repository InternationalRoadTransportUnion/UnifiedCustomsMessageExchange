package org.iru.rtsplus.client.classic;

import java.io.Serializable;
import java.lang.reflect.UndeclaredThrowableException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.namespace.QName;

import org.iru.model.tir_actor_1.Customs;
import org.iru.model.tir_actor_1.IRU;
import org.iru.rts.client.ReconciliationClient;
import org.iru.rts.client.ReturnCode;
import org.iru.rts.client.classic.AbstractClient;
import org.iru.rts.client.classic.ReconciliationClientImpl;
import org.iru.rts.client.classic.UploadClientImpl;
import org.iru.rts.model.termination_1.MissingTIROperationTerminationType;
import org.iru.rts.model.termination_1.ReconciliationRequestReasonType;
import org.iru.rts.model.termination_1.ReconciliationRequestRepliesType;
import org.iru.rts.model.termination_1.ReconciliationRequestReplyType;
import org.iru.rts.model.termination_1.ReconciliationRequestType;
import org.iru.rts.model.termination_1.ReconciliationRequestType.Originator;
import org.iru.rts.model.termination_1.TIROperationTerminationType;
import org.iru.rts.model.termination_1.TIROperationTerminationsType;
import org.iru.rts.model.termination_1.UpdatedTIROperationTerminationType;
import org.iru.rts.safetirreconciliation.RequestRecord;
import org.iru.rts.safetirupload.CWRType;
import org.iru.rts.safetirupload.PFDType;
import org.iru.rts.safetirupload.Records;
import org.iru.rts.safetirupload.Records.Record;
import org.iru.rts.safetirupload.RequestReplyRecords;
import org.iru.rts.safetirupload.TCOType;
import org.iru.rts.safetirupload.UPGType;
import org.iru.rtsplus.client.TerminationServiceClient;

import jakarta.xml.bind.JAXBElement;
import jakarta.xml.ws.WebServiceException;

public class TerminationServiceClientImpl extends AbstractWSSClient implements TerminationServiceClient {

	private UploadClientImpl upload;
	private Object uploadLock = new Object();
	private boolean uploadSet;
	private ReconciliationClient reconciliation;
	private Object reconciliationLock = new Object();
	private boolean reconciliationSet;
	
	public void transmitTIROperationTerminations(TIROperationTerminationsType tirOperationTerminations, String transmissionId) throws DatatypeConfigurationException {
		transmitTIROperationTerminations(tirOperationTerminations, transmissionId, new Date());
	}

	protected UploadClientImpl getUpload() {
		return new UploadClientImpl();
	}
	
	protected ReconciliationClient getReconciliation() {
		return new ReconciliationClientImpl();
	}
	
	private void setUpload() {
		synchronized (uploadLock) {
			if (! uploadSet) {
				try {
					upload = getUpload();
					updateClientSettings(upload);
				} finally {
					uploadSet = true;
				}
			}
		}
	}
	
	private static Record convertTIROperationTerminationToRecord(TIROperationTerminationType termination, boolean isNewRecord) {
		Record r = new Record();
		
		r.setTNO(termination.getTIRCarnetNumber());
		r.setVPN(termination.getVoletPageNumber() != null ? BigInteger.valueOf(termination.getVoletPageNumber()) : BigInteger.ZERO);
		r.setICC(termination.getCustoms().getCountryCode());
		r.setCOF(termination.getCustomsOffice());
		r.setCNL(termination.getCustomsLedgerEntryReference());
		r.setDCL(termination.getCustomsLedgerEntryDate());
		r.setRND(termination.getCertificateOfTerminationReference());
		r.setDDI(termination.getCertificateOfTerminationDate());
		r.setPFD(Boolean.TRUE.equals(termination.isIsBeforeLoad()) || Boolean.TRUE.equals(termination.isIsExit()) ? null : Boolean.TRUE.equals(termination.isIsFinal()) ? PFDType.FD : PFDType.PD);
		r.setCWR(termination.isIsWithReservation() ? CWRType.R : CWRType.OK);
		r.setTCO(Boolean.TRUE.equals(termination.isIsBeforeLoad()) ? TCOType.LOAD : Boolean.TRUE.equals(termination.isIsExit()) ? TCOType.EXIT : null);
		r.setCOM(termination.getCustomsComment());
		r.setUPG(isNewRecord ? UPGType.N : UPGType.C);
		r.setPIC(termination.getPackageCount() != null ? BigInteger.valueOf(termination.getPackageCount()) : null);
		return r;
	}
	
	private static int parseReplyType(String type) {
		if (type.equals("CONFIRMED"))
			return 1;
		if (type.equals("CORRECTED"))
			return 2;
		return 3; // NOT_FOUND
	}
	
	private static RequestReplyRecords.RequestReplyRecord convertReconciliationRequestReplyToRequestReplyRecord(ReconciliationRequestReplyType rrr) {
		RequestReplyRecords.RequestReplyRecord r = new RequestReplyRecords.RequestReplyRecord();

		r.setRequestID(rrr.getId());
		r.setRequestReplyType(parseReplyType(rrr.getReplyType()));
		
		TIROperationTerminationType termination = rrr.getCorrectedTIROperationTermination();
		if (termination != null) { 
			r.setTNO(termination.getTIRCarnetNumber());
			r.setVPN(termination.getVoletPageNumber() != null ? BigInteger.valueOf(termination.getVoletPageNumber()) : BigInteger.ZERO);
			r.setICC(termination.getCustoms().getCountryCode());
			r.setCOF(termination.getCustomsOffice());
			r.setCNL(termination.getCustomsLedgerEntryReference());
			r.setDCL(termination.getCustomsLedgerEntryDate());
			r.setRND(termination.getCertificateOfTerminationReference());
			r.setDDI(termination.getCertificateOfTerminationDate());
			r.setPFD(Boolean.TRUE.equals(termination.isIsBeforeLoad()) || Boolean.TRUE.equals(termination.isIsExit()) ? null : Boolean.TRUE.equals(termination.isIsFinal()) ? PFDType.FD : PFDType.PD);
			r.setCWR(termination.isIsWithReservation() ? CWRType.R : CWRType.OK);
			r.setTCO(Boolean.TRUE.equals(termination.isIsBeforeLoad()) ? TCOType.LOAD : Boolean.TRUE.equals(termination.isIsExit()) ? TCOType.EXIT : null);
			r.setCOM(termination.getCustomsComment());
			r.setPIC(termination.getPackageCount() != null ? BigInteger.valueOf(termination.getPackageCount()) : null);
		}
		return r;
	}
	
	private static ReconciliationRequestType convertRequestRecordToReconciliationRequest(RequestRecord record) {
		ReconciliationRequestType rr = new ReconciliationRequestType();
		
		rr.setId(record.getRequestID());
		rr.setDate(record.getRequestDate());
		rr.setReminderCount(record.getRequestReminderNum());
		Originator orig = new Originator();
		orig.setIRU(new IRU());
		rr.setOriginator(orig);
		rr.setRemark(record.getRequestRemark());
		
		int rds = record.getRequestDataSource();
		boolean missing = rds == 1; // TIR Carnet data
				
		if (missing) {
			MissingTIROperationTerminationType termination = new MissingTIROperationTerminationType();
			termination.setTIRCarnetNumber(record.getTNO());
			Customs c = new Customs();
			c.setCountryCode(record.getICC());
			termination.setCustoms(c);
			termination.setVoletPageNumber(record.getVPN() != null && !BigInteger.ZERO.equals(record.getVPN()) ? record.getVPN().shortValue() : null);

			termination.setCustomsOffice(record.getCOF());
			
			termination.setCustomsLedgerEntryDate(record.getDCL());
			termination.setCustomsLedgerEntryReference(record.getCNL());
			termination.setCertificateOfTerminationDate(record.getDDI());
			termination.setCertificateOfTerminationReference(record.getRND());
			
			if (record.getTCO() == null && record.getPFD() != null)
				termination.setIsFinal(PFDType.FD.equals(record.getPFD()));

			/* TODO?: extract the termination number which can be append to PFD
			 * from 3rd character and pass it to termination.setSequenceNumber
			 */
			if (record.getCWR() != null)
				termination.setIsWithReservation(CWRType.R.equals(record.getCWR()));

			termination.setIsBeforeLoad(TCOType.LOAD.equals(record.getTCO()) ? true : null);
			termination.setIsExit(TCOType.EXIT.equals(record.getTCO()) ? true : null);
			
			termination.setCustomsComment(record.getCOM());
			termination.setPackageCount(record.getPIC() != null ? record.getPIC().longValue() : null);

			rr.setMissingTIROperationTermination(termination);
			rr.setReason(ReconciliationRequestReasonType.MISSING);
		} else {
			TIROperationTerminationType termination = new TIROperationTerminationType();
			termination.setTIRCarnetNumber(record.getTNO());
			Customs c = new Customs();
			c.setCountryCode(record.getICC());
			termination.setCustoms(c);
			termination.setVoletPageNumber(record.getVPN() != null && !BigInteger.ZERO.equals(record.getVPN()) ? record.getVPN().shortValue() : null);
			termination.setCustomsOffice(record.getCOF());
			
			termination.setCustomsLedgerEntryDate(record.getDCL());
			termination.setCustomsLedgerEntryReference(record.getCNL());
			termination.setCertificateOfTerminationDate(record.getDDI());
			termination.setCertificateOfTerminationReference(record.getRND());
			
			if (record.getTCO() == null && record.getPFD() != null)
				termination.setIsFinal(PFDType.FD.equals(record.getPFD()));

			/* TODO?: extract the termination number which can be append to PFD
			 * from 3rd character and pass it to termination.setSequenceNumber
			 */
			termination.setIsWithReservation(CWRType.R.equals(record.getCWR()));

			termination.setIsBeforeLoad(TCOType.LOAD.equals(record.getTCO()) ? true : null);
			termination.setIsExit(TCOType.EXIT.equals(record.getTCO()) ? true : null);
			
			termination.setCustomsComment(record.getCOM());
			termination.setPackageCount(record.getPIC() != null ? record.getPIC().longValue() : null);

			rr.setTIROperationTerminationToValidate(termination);
			rr.setReason(ReconciliationRequestReasonType.DISCREPANCY);
		}
		
		return rr;
	}

	@Override
	public void transmitTIROperationTerminations(TIROperationTerminationsType tirOperationTerminations, String transmissionId, Date transmissionTime) throws DatatypeConfigurationException {
		setUpload();
	
		List<Record> safeTIRRecords = new ArrayList<Records.Record>(tirOperationTerminations.getCount().intValue());
		
		for (JAXBElement<? extends Serializable> xTerm : tirOperationTerminations.getNewTIROperationTerminationOrCancelledTIROperationTerminationOrUpdatedTIROperationTermination()) {
			Object term = xTerm.getValue();
			if (term instanceof TIROperationTerminationType) {
				QName name = xTerm.getName();
				safeTIRRecords.add(convertTIROperationTerminationToRecord((TIROperationTerminationType) term, name.getLocalPart().startsWith("New")));
			} else if (term instanceof UpdatedTIROperationTerminationType) {
				UpdatedTIROperationTerminationType ut = (UpdatedTIROperationTerminationType) term;
				safeTIRRecords.add(convertTIROperationTerminationToRecord(ut.getCancelledTIROperationTermination(), false));
				safeTIRRecords.add(convertTIROperationTerminationToRecord(ut.getNewTIROperationTermination(), true));
			}
		}
		
		try {
			ReturnCode rc = upload.wsst(safeTIRRecords, transmissionId, transmissionTime);
			if (rc != ReturnCode.SUCCESS)
				throw new WebServiceException("wsst returned "+rc+"("+rc.codeValue()+")");
		} catch (Exception e) {
			if (e instanceof RuntimeException)
				throw (RuntimeException) e;
			throw new UndeclaredThrowableException(e);
		}
	}

	@Override
	public Set<ReconciliationRequestType> getReconciliationRequests(Date from, Date to, Long retrievalRange) throws DatatypeConfigurationException {
		synchronized (reconciliationLock) {
			if (! reconciliationSet) {
				try {
					reconciliation = getReconciliation();
					updateClientSettings((AbstractClient) reconciliation);
				} finally {
					reconciliationSet = true;
				}
			}
		}
		
		Set<ReconciliationRequestType> matching = new LinkedHashSet<ReconciliationRequestType>();
		
		try {
			List<RequestRecord> records = reconciliation.downloadReconciliationRequests(UUID.randomUUID().toString());
			for (RequestRecord record : records) {
				Date requestDate = record.getRequestDate().toGregorianCalendar().getTime();
				if ((from == null || requestDate.after(from)) && (to == null || requestDate.before(to))) {
					matching.add(convertRequestRecordToReconciliationRequest(record));
				}
			}
		} catch (Exception e) {
			if (e instanceof RuntimeException)
				throw (RuntimeException) e;
			throw new UndeclaredThrowableException(e);
		}
		
		return matching;
	}

	@Override
	public void transmitReconciliationRequestReplies(ReconciliationRequestRepliesType reconciliationRequestReplies, String transmissionId, Date transmissionTime) throws DatatypeConfigurationException {
		setUpload();
		
		List<RequestReplyRecords.RequestReplyRecord> rrRecords = new ArrayList<RequestReplyRecords.RequestReplyRecord>(reconciliationRequestReplies.getCount().intValue());
		
		for (ReconciliationRequestReplyType rrr : reconciliationRequestReplies.getReconciliationRequestReply()) {
			rrRecords.add(convertReconciliationRequestReplyToRequestReplyRecord(rrr));
		}
		
		try {
			ReturnCode rc = upload.wsre(rrRecords, transmissionId);
			if (rc != ReturnCode.SUCCESS)
				throw new WebServiceException("wsre returned "+rc+"("+rc.codeValue()+")");
		} catch (Exception e) {
			if (e instanceof RuntimeException)
				throw (RuntimeException) e;
			throw new UndeclaredThrowableException(e);
		}
	}

	 
}
