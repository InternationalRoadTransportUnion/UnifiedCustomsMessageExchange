package org.iru.tirepd.ws.b2g.base;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

import javax.xml.stream.XMLStreamException;

import org.iru.common.crypto.wscrypto.CipheredData;
import org.iru.common.crypto.wscrypto.Decrypter;
import org.iru.rts.ws.tirepd_b2g_1.TIREPDB2GServiceClassSoap;
import org.iru.rts.ws.tirepd_b2g_1.TIREPDB2GUploadAck;
import org.iru.rts.ws.tirepd_b2g_1.TIREPDB2GUploadParams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.xml.bind.JAXBException;

/**
 * AbstractB2GService is the base implementation that knows the details of the
 * B2G protocol (in particular the error codes). Subclasses should not only have
 * to implement the abstract methods.
 */
public abstract class AbstractB2GService implements TIREPDB2GServiceClassSoap {

	private static final Logger log = LoggerFactory.getLogger(AbstractB2GService.class);

	protected abstract byte[] lookupPrivateKey(String certificateThumbprint, String subscriber);

	protected abstract Class<?> lookupMessageName(String messageName);

	protected abstract void processMessageContent(String subscriberMessageID, Object messageContent, String messageName)
			throws Exception;

	protected abstract String getHostID();

	protected TIREPDB2GUploadAck ackMessage(String subscriberMessageID, int returnCode) {
		return ackMessage(subscriberMessageID, returnCode, null);
	}

	protected TIREPDB2GUploadAck ackMessage(String subscriberMessageID, int returnCode, Throwable cause) {
		if (returnCode == 2) {
			log.debug(subscriberMessageID + " acked successfully");
		} else {
			log.warn("subscriberMessageID '" + subscriberMessageID + "' returned " + returnCode, cause);
		}
		TIREPDB2GUploadAck ack = new TIREPDB2GUploadAck();
		ack.setHostID(getHostID());
		ack.setSubscriberMessageID(subscriberMessageID);
		ack.setReturnCode(returnCode);
		return ack;
	}

	@Override
	public TIREPDB2GUploadAck tirepdb2G(TIREPDB2GUploadParams su) {

		String subscriberMessageID = su.getSubscriberMessageID();
		if (subscriberMessageID == null)
			return ackMessage(subscriberMessageID, 1214);

		String subscriber = su.getSubscriberID();
		if (subscriber == null)
			return ackMessage(subscriberMessageID, 1210);

		byte[] privateKey = lookupPrivateKey(su.getCertificateID(), subscriber);

		if (privateKey == null)
			return ackMessage(subscriberMessageID, 1211);

		Decrypter dec = new Decrypter();
		try {
			dec.setPrivateKeyDER(privateKey);
		} catch (GeneralSecurityException e) {
			return ackMessage(subscriberMessageID, 1211, e);
		} catch (IOException e) {
			return ackMessage(subscriberMessageID, 1200, e);
		}

		CipheredData data = new CipheredData();
		byte[] messageContent = su.getMessageContent();
		if (messageContent == null)
			return ackMessage(subscriberMessageID, 1218);
		data.setPayload(messageContent);
		byte[] eSessionKey = su.getESessionKey();
		if (eSessionKey == null)
			return ackMessage(subscriberMessageID, 1213);
		data.setSessionKey(eSessionKey);

		String mn = su.getMessageName();
		Class<?> contentClass = lookupMessageName(mn);
		if (contentClass == null)
			return ackMessage(subscriberMessageID, 1216);

		Object content;
		try {
			content = dec.decryptPayload(data, contentClass);
		} catch (JAXBException e) {
			return ackMessage(subscriberMessageID, 1302, e);
		} catch (InvalidKeyException e) {
			return ackMessage(subscriberMessageID, 1213, e);
		} catch (GeneralSecurityException e) {
			return ackMessage(subscriberMessageID, 1301, e);
		} catch (XMLStreamException e) {
			return ackMessage(subscriberMessageID, 1302, e);
		}
		
		try {
			processMessageContent(subscriberMessageID, content, mn);
		} catch (Exception e) {
			return ackMessage(subscriberMessageID, 1200, e);
		}
		
		return ackMessage(subscriberMessageID, 2);
	}

}
