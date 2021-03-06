package org.iru.rtsplus.client.plus;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.logging.Logger;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import javax.xml.soap.SOAPPart;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.Service;
import javax.xml.ws.handler.Handler;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;
import javax.xml.ws.soap.AddressingFeature;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoBase;
import org.apache.ws.security.components.crypto.CryptoType;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.message.WSSecTimestamp;
import org.apache.ws.security.message.WSSecUsernameToken;
import org.apache.ws.security.util.WSSecurityUtil;

public abstract class AbstractWSSClient  {

	protected static final String WS_ADDRESSING_NAMESPACE  = "http://www.w3.org/2005/08/addressing";
	
	protected String sender;
	protected String password; 
	protected URL rtsEndpoint;
	
	protected String portNameSuffix = "";

	protected RSAPrivateKey signingKey;
	private X509Certificate signingCertificate;
	private X509Certificate verifyingCertificate;
	
	public static X509Certificate loadCertificate(byte[] cert) throws CertificateException {
		CertificateFactory x509CertFact = CertificateFactory.getInstance("X.509");
		ByteArrayInputStream in = new ByteArrayInputStream(cert);
		try {
			return (X509Certificate) x509CertFact.generateCertificate(in);
		} finally {
			try {
				in.close();
			} catch (IOException e) {
				// impossible, so rethrow as CertificateException
				throw new CertificateException(e);
			}
		}
	}
	
	public static String getThumbprint(X509Certificate cert) throws CertificateEncodingException {
		return DigestUtils.sha1Hex(cert.getEncoded());
	}
	
	protected static XMLGregorianCalendar convertToXML(Date d) throws DatatypeConfigurationException  {
		if (d == null)
			return null;
		GregorianCalendar gCalendar = new GregorianCalendar();
		gCalendar.setTime(d);
		return DatatypeFactory.newInstance().newXMLGregorianCalendar(gCalendar);
	}
	
	public void setSender(String sender) {
		this.sender = sender;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public void setRtsEndpoint(URL rtsEndpoint) {
		this.rtsEndpoint = rtsEndpoint;
	}

	public void setCertificate(byte[] iruCertificate) throws CertificateEncodingException, CertificateException {
		setPassword(getThumbprint(loadCertificate(iruCertificate)).toUpperCase(Locale.ENGLISH));
	}

	public void setSigningCertificateDER(byte[] signingCertificate) throws CertificateEncodingException, CertificateException {
		this.signingCertificate = loadCertificate(signingCertificate);
	}

	public void setVerifyingCertificateDER(byte[] verifyingCertificate) throws CertificateEncodingException, CertificateException {
		this.verifyingCertificate = loadCertificate(verifyingCertificate);
	}
	
	
	public void setSigningKeyDER(byte[] signingKey) throws GeneralSecurityException {
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		KeySpec ks = new PKCS8EncodedKeySpec(signingKey);
		this.signingKey = (RSAPrivateKey) keyFactory.generatePrivate(ks);	
	}
	
	public void setPortNameSuffix(String portNameSuffix) {
		this.portNameSuffix = portNameSuffix;
	}
	
	protected QName getServiceQName() {
		throw new UnsupportedOperationException();
	}
	
	protected <S extends Service> QName getPortQName() {
		throw new UnsupportedOperationException();
	}
	
	protected <T> T getWsPort(Class<? extends Service> svcClass, Class<T> seiClass) {
		T wsPort;
		try {
			Service service = svcClass.getConstructor(URL.class, QName.class).newInstance(rtsEndpoint, getServiceQName());
			wsPort = service.getPort(getPortQName(), seiClass, new AddressingFeature());
		} catch (Exception e) {
			throw new IllegalArgumentException(e);
		}
		addSecurityHeader(wsPort);
		return wsPort;
	}

	protected void addSecurityHeader(Object wsPort) {
		BindingProvider servicePort = (BindingProvider) wsPort;
		@SuppressWarnings("rawtypes")
		List<Handler> handlers = servicePort.getBinding().getHandlerChain();
		SOAPHandler<SOAPMessageContext> authHandler = new SOAPHandler<SOAPMessageContext>() {

			@Override
			public boolean handleMessage(SOAPMessageContext context) {
				SOAPPart envelope = context.getMessage().getSOAPPart();
				if ((Boolean) context.get(SOAPMessageContext.MESSAGE_OUTBOUND_PROPERTY)) {

					if (sender != null && password != null) {
						// create wsse:UsernameToken to pass username
						WSSecUsernameToken usernameToken = new WSSecUsernameToken();
						usernameToken.setPasswordType(WSConstants.PASSWORD_DIGEST);
						usernameToken.setUserInfo(sender, password);
	
						// add wsse:Security and add all sub-elements
						WSSecHeader secHeader = new WSSecHeader();
						try {
							secHeader.insertSecurityHeader(envelope);
							usernameToken.build(envelope, secHeader);
						} catch (WSSecurityException e) {
							throw new SecurityException(e);
						}
					} else if (signingKey != null) {
						Crypto crypto = new CryptoBase() {
							
							@Override
							public boolean verifyTrust(X509Certificate[] certs, boolean enableRevocation)
									throws WSSecurityException {
								Logger.getLogger(getClass().getName()).warning("verifyTrust(certs, enableRevocation)");
								throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
							}
							
							@Override
							public boolean verifyTrust(PublicKey publicKey) throws WSSecurityException {
								Logger.getLogger(getClass().getName()).warning("verifyTrust(publicKey)");
								throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
							}
							
							@Override
							public boolean verifyTrust(X509Certificate[] certs)
									throws WSSecurityException {
								Logger.getLogger(getClass().getName()).warning("verifyTrust(certs)");
								throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
							}
							
							@Override
							public String getX509Identifier(X509Certificate cert)
									throws WSSecurityException {
								Logger.getLogger(getClass().getName()).warning("getX509Identifier()");
								throw new WSSecurityException(WSSecurityException.FAILURE);
							}
							
							@Override
							public X509Certificate[] getX509Certificates(CryptoType cryptoType)
									throws WSSecurityException {
								return new X509Certificate[] { signingCertificate } ;
							}
							
							@Override
							public PrivateKey getPrivateKey(String identifier, String password)
									throws WSSecurityException {
								return signingKey;
							}
							
							@Override
							public PrivateKey getPrivateKey(X509Certificate certificate,
									CallbackHandler callbackHandler) throws WSSecurityException {
								Logger.getLogger(getClass().getName()).warning("getPrivateKey(certificate, callbackHandler)");
								throw new WSSecurityException(WSSecurityException.FAILURE);
							}
						};
						
						WSSecHeader secHeader = new WSSecHeader();
						try {
							secHeader.insertSecurityHeader(envelope);
							WSSecTimestamp ts = new WSSecTimestamp();
							ts.build(envelope, secHeader);
							WSSecSignature sign = new WSSecSignature();
							sign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
							
							List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>(3);
				            String soapNamespace = WSSecurityUtil.getSOAPNamespace(envelope.getDocumentElement());
				            String encMod = "Element"; // "Content"
							WSEncryptionPart bodyEncPart = new WSEncryptionPart(WSConstants.ELEM_BODY, soapNamespace, encMod);
							parts.add(bodyEncPart);
							
							WSEncryptionPart tsEncPart = new WSEncryptionPart(ts.getId(), encMod);
							parts.add(tsEncPart);
													
							String[] policyAddrEncParts = { "MessageID", "RelatesTo", "To", "Action", "From", "ReplyTo", "FaultTo" };
							for (String policyAddrEncPart : policyAddrEncParts){ 
								if (WSSecurityUtil.findElement(envelope, policyAddrEncPart, WS_ADDRESSING_NAMESPACE) != null) {
									WSEncryptionPart actionEncPart = new WSEncryptionPart(policyAddrEncPart, WS_ADDRESSING_NAMESPACE, encMod);
									parts.add(actionEncPart);
								}
							}
							
							sign.setParts(parts);
							
							sign.build(envelope, crypto, secHeader);
						} catch (WSSecurityException e) {
							throw new SecurityException(e);
						}
						
					} 
				} else {
					if (verifyingCertificate != null) {
						WSSecurityEngine eng = new WSSecurityEngine();
						
						Crypto crypto = new CryptoBase() {
							
							@Override
							public boolean verifyTrust(X509Certificate[] certs, boolean enableRevocation)
									throws WSSecurityException {
								Logger.getLogger(getClass().getName()).warning("verifyTrust(certs, enableRevocation)");
								throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
							}
							
							@Override
							public boolean verifyTrust(PublicKey publicKey) throws WSSecurityException {
								Logger.getLogger(getClass().getName()).warning("verifyTrust(publicKey)");
								throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
							}
							
							@Override
							public boolean verifyTrust(X509Certificate[] certs)
									throws WSSecurityException {
								Logger.getLogger(getClass().getName()).warning("verifyTrust(certs)");
								throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
							}
							
							@Override
							public String getX509Identifier(X509Certificate cert)
									throws WSSecurityException {
								Logger.getLogger(getClass().getName()).warning("getX509Identifier()");
								throw new WSSecurityException(WSSecurityException.FAILURE);
							}
							
							@Override
							public X509Certificate[] getX509Certificates(CryptoType cryptoType)
									throws WSSecurityException {
								return new X509Certificate[] { verifyingCertificate };
							}
							
							@Override
							public PrivateKey getPrivateKey(String identifier, String password)
									throws WSSecurityException {
								Logger.getLogger(getClass().getName()).warning("getPrivateKey(identifier, password)");
								throw new WSSecurityException(WSSecurityException.FAILURE);
							}
							
							@Override
							public PrivateKey getPrivateKey(X509Certificate certificate,
									CallbackHandler callbackHandler) throws WSSecurityException {
								Logger.getLogger(getClass().getName()).warning("getPrivateKey(certificate, callbackHandler)");
								throw new WSSecurityException(WSSecurityException.FAILURE);
							}
						};
						
						
						try {
							eng.processSecurityHeader(envelope, null, null, crypto);
						} catch (WSSecurityException e) {
							throw new SecurityException(e);
						}
					}
				}

				return true;
			}

			@Override
			public boolean handleFault(SOAPMessageContext context) {
				return true;
			}

			@Override
			public void close(MessageContext context) {
			}


			@Override
			public Set<QName> getHeaders() {
				return Collections.singleton(new QName("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "Security"));
			}

		};
		handlers.add(authHandler);
		// add back handlers (if it was null/empty, it's not attached to the binding)
		servicePort.getBinding().setHandlerChain(handlers); 
	}

}
