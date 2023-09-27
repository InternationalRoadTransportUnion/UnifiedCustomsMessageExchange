package org.iru.rts.client.classic;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.security.cert.CertificateException;
import java.util.Map;

import jakarta.xml.ws.BindingProvider;

import org.apache.commons.io.FileUtils;
import org.iru.common.crypto.wscrypto.Encrypter;

public class AbstractClient {

	protected String sender;
	protected String password; 
	protected URL rtsEndpoint;
	protected Map<String, Object> bindingProviderRequestContext;
	
	byte[] iruCertificate;

	public void setSender(String sender) {
		this.sender = sender;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public void setIruCertificate(File iruCertificate) throws IOException {
		byte[] certByteArray = FileUtils.readFileToByteArray(iruCertificate);
		setIruCertificateData(certByteArray);
	}

	public void setIruCertificateData(byte[] certByteArray) {
		this.iruCertificate = certByteArray;
	}

	public void setRtsEndpoint(URL rtsEndpoint) {
		this.rtsEndpoint = rtsEndpoint;
	}
	
	public void setBindingProviderRequestContext(Map<String, Object> bindingProviderRequestContext) {
		this.bindingProviderRequestContext = bindingProviderRequestContext;
	}

	protected Encrypter makeEncrypter() throws CertificateException {
		Encrypter enc = new Encrypter();
		enc.setCertificate(iruCertificate);
		return enc;
	}
	
	protected void putAllBindingProviderRequestContext(Object wsPort) {
		if (bindingProviderRequestContext != null) {
			BindingProvider bprov = (BindingProvider) wsPort;
			bprov.getRequestContext().putAll(bindingProviderRequestContext);
		}
	}
	
	
}
