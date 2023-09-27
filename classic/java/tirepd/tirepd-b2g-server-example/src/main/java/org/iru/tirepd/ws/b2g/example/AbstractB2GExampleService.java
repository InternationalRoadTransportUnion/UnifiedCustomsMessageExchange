package org.iru.tirepd.ws.b2g.example;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.apache.commons.io.IOUtils;
import org.iru.common.crypto.wscrypto.CryptoUtil;
import org.iru.rts.ws.tirepd_b2g_1.TIREPDB2GUploadAck;
import org.iru.rts.ws.tirepd_b2g_1.TIREPDB2GUploadParams;
import org.iru.tirepd.ws.b2g.base.AbstractB2GService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.annotation.Resource;
import jakarta.servlet.ServletContext;
import jakarta.xml.ws.WebServiceContext;
import jakarta.xml.ws.handler.MessageContext;

/**
 * AbstractB2GExampleService shows how to create a subclass of AbstractB2GService
 * which uses lazy initialization of key and certificate (hence the use of 
 * tirepdb2G method) embedded in the application. It is thus very simple,
 * but not good for production as the keys and certificates ought to be
 * managed outside of the application.
 */
public abstract class AbstractB2GExampleService extends AbstractB2GService {

	protected final Logger log = LoggerFactory.getLogger(getClass());
	
	private Object initLock = new Object();
	private boolean inited = false;
	private byte[] privateKey;
	private String certTP;
	protected String subscriber;
	
	@Resource 
	protected WebServiceContext context;

	@Override
	protected String getHostID() {
		try {
			return InetAddress.getLocalHost().getHostName();
		} catch (UnknownHostException e) {
			log.warn(e.getLocalizedMessage(), e);
			return "localhost";
		}
	}

	@Override
	protected byte[] lookupPrivateKey(String certificateThumbprint,
			String subscriber) {
		if (certTP.equals(certificateThumbprint.toLowerCase()) && this.subscriber.equals(subscriber))
			return privateKey;
		return null;
	}

	
	@Override
	public TIREPDB2GUploadAck tirepdb2G(TIREPDB2GUploadParams su) {
		synchronized (initLock) {
			if (! inited) {
				
				MessageContext mctx = context.getMessageContext();
				ServletContext sctx = (ServletContext) mctx.get(MessageContext.SERVLET_CONTEXT);
				
				String pkf = sctx.getInitParameter("PrivateKeyFile");
				try {
					privateKey = IOUtils.toByteArray(Thread.currentThread().getContextClassLoader().getResourceAsStream(pkf)); 
				} catch (Exception e) {
					log.warn("Could not load PrivateKeyFile: "+pkf, e);
					return ackMessage(null, 1200);
				}
				
				String cf = sctx.getInitParameter("CertificateFile");
				try {
					certTP = CryptoUtil.getThumbprint(CryptoUtil.loadCertificate(IOUtils.toByteArray(Thread.currentThread().getContextClassLoader().getResourceAsStream(cf))));
				} catch (Exception e) {
					log.warn("Could not load CertificateFile: "+cf, e);
					return ackMessage(null, 1200);
				}
				
				subscriber = sctx.getInitParameter("Subscriber");
				
				inited = true;
			}
		}		
		
		return super.tirepdb2G(su);
	}

}
