package org.iru.tirepd.ws.b2g.example;

import java.io.StringWriter;

import javax.xml.XMLConstants;
import javax.xml.namespace.QName;

import org.iru.epd.model.message.envelope.AttachmentType;
import org.iru.epd.model.message.envelope.BinaryAttachmentType;
import org.iru.epd.model.message.envelope.EnvelopeType;
import org.iru.epd.model.message.envelope.XMLTypeType;
import org.iru.rts.ws.tirepd_b2g_1.TIREPDB2GUploadAck;
import org.iru.rts.ws.tirepd_b2g_1.TIREPDB2GUploadParams;
import org.iru.tirepd.messages.names.NoNamespaceMapper;
import org.w3c.dom.Element;

import jakarta.jws.WebService;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.bind.Unmarshaller;

/**
 * AsyncB2GExampleObjectLoggingService is a complete implementation of B2G endpoint,
 * which does nothing with the message content it received. A real
 * implementation should push the message for asynchronous processing
 * (for instance, by using a JMS queue in JEE environment).
 */
@WebService(endpointInterface="org.iru.rts.ws.tirepd_b2g_1.TIREPDB2GServiceClassSoap")
public class AsyncB2GExampleObjectLoggingService extends AbstractB2GExampleService {

	@Override
	protected Class<?> lookupMessageName(String messageName) {
		return NoNamespaceMapper.getB2GClass(messageName);
	}

	private void info(String messageName, Object messageContent) throws JAXBException {
		JAXBContext context = JAXBContext.newInstance(messageContent.getClass());
		Marshaller m = context.createMarshaller();
		m.setProperty(Marshaller.JAXB_ENCODING, "UTF-8");
		m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
		m.setProperty(Marshaller.JAXB_FRAGMENT, true);
		StringWriter sw = new StringWriter();
		m.marshal(messageContent, sw);
		log.info(messageName+" => "+sw);
	}
	
	@Override
	protected void processMessageContent(String subscriberMessageID, Object messageContent, String messageName)
			throws Exception {
		if (messageContent instanceof EnvelopeType) {
			EnvelopeType envelope = (EnvelopeType) messageContent;
			XMLTypeType bodyType = envelope.getHeader().getBodyType();
			QName bodyElementQName = bodyType.getElement();
			Class<?> bodyClass;
			if (bodyElementQName.getNamespaceURI().equals(XMLConstants.NULL_NS_URI)) {
				String simpleClassName = bodyElementQName.getLocalPart();
				bodyClass = Thread.currentThread().getContextClassLoader().loadClass("org.iru.epd.model.message.nons."+simpleClassName);
				Object body = envelope.getBody().getAny();
				Element bodyElement = (Element) body;
				JAXBContext context = JAXBContext.newInstance(bodyClass);
				Unmarshaller m = context.createUnmarshaller();
				messageContent = m.unmarshal(bodyElement);
				info("Body: "+simpleClassName, messageContent);
			} else {
				log.warn("Unknown body type: "+bodyElementQName);
			}
			
			for (AttachmentType attachment : envelope.getAttachments().getAttachment()) {
				String attachmentId = attachment.getAttachmentId();
				BinaryAttachmentType binary = attachment.getBinaryAttachment();
				String attachmentName = binary.getAttachmentName();
				String attachmentContentType = binary.getData().getContentType();
				byte[] attachmentContent = binary.getData().getValue();
				log.info("Attachment["+attachmentId+"]: with name '"+attachmentName+"' and mime type '"+attachmentContentType+"', of size "+attachmentContent.length);
			}
		} else {
			info(messageName, messageContent);
		}
	}

	/*
	 * WAS needs the methods in the WebService class, even if superclass already implements it 
	 */
	@Override
	public TIREPDB2GUploadAck tirepdb2G(TIREPDB2GUploadParams su) {
		return super.tirepdb2G(su);
	}



}
