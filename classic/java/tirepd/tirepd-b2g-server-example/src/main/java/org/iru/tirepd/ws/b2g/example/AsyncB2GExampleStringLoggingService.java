package org.iru.tirepd.ws.b2g.example;

import jakarta.jws.WebService;

import org.iru.rts.ws.tirepd_b2g_1.TIREPDB2GUploadAck;
import org.iru.rts.ws.tirepd_b2g_1.TIREPDB2GUploadParams;

/**
 * AsyncB2GExampleStringLoggingService is a complete implementation of B2G endpoint,
 * which does nothing with the message content it received. A real
 * implementation should push the message for asynchronous processing
 * (for instance, by using a JMS queue in JEE environment).
 */
@WebService(endpointInterface="org.iru.rts.ws.tirepd_b2g_1.TIREPDB2GServiceClassSoap")
public class AsyncB2GExampleStringLoggingService extends AbstractB2GExampleService {

	@Override
	protected Class<?> lookupMessageName(String messageName) {
		return String.class;
	}

	@Override
	protected void processMessageContent(String subscriberMessageID, Object messageContent, String messageName)
			throws Exception {
		String message = (String) messageContent;
		log.info(messageName+" => "+message);
	}

	/*
	 * WAS needs the methods in the WebService class, even if superclass already implements it 
	 */
	@Override
	public TIREPDB2GUploadAck tirepdb2G(TIREPDB2GUploadParams su) {
		return super.tirepdb2G(su);
	}



}
