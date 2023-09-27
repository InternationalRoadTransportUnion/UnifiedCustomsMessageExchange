package org.iru.common.crypto.wscrypto;

import java.io.IOException;
import java.io.StringReader;
import java.lang.reflect.InvocationTargetException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.regex.Matcher;

import javax.crypto.Cipher;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import org.apache.commons.codec.digest.DigestUtils;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Unmarshaller;

public class Decrypter {

	RSAPrivateKey privKey;

	public void setPrivateKeyDER(byte[] key) throws GeneralSecurityException, IOException {
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		KeySpec ks = new PKCS8EncodedKeySpec(key);
		privKey = (RSAPrivateKey) keyFactory.generatePrivate(ks);
	}

	public Object decryptPayload(CipheredData cdata, Class<?> payloadClazz)
			throws JAXBException, GeneralSecurityException, XMLStreamException {
		
		Cipher rsaCipher = Cipher.getInstance(CryptoUtil.RSA_CIPHER);
	    rsaCipher.init(Cipher.UNWRAP_MODE, privKey);
	    
	    Key key = rsaCipher.unwrap(cdata.getSessionKey(), CryptoUtil.TRIPLE_DES_ALGO, Cipher.SECRET_KEY);
	    
		Cipher cipher = Cipher.getInstance(CryptoUtil.TRIPLE_DES_CIPHER);
	    cipher.init(Cipher.DECRYPT_MODE, key, CryptoUtil.IV_SPEC);
	    byte[] b = cipher.doFinal(cdata.getPayload());
	    
	    if (payloadClazz.equals(byte[].class))
	    	return b;
	    
	    String stringResponse = new String(b, CryptoUtil.UNICODE_CHARSET);
	    
	    if (payloadClazz.equals(String.class))
	    	return stringResponse;
		
	    JAXBContext context = JAXBContext.newInstance(payloadClazz);
		Unmarshaller m = context.createUnmarshaller();
		Object result = null;
		try {
			result = m.unmarshal(new StringReader(stringResponse));
		} catch (JAXBException e) {
			XMLInputFactory xif = XMLInputFactory.newFactory();
			XMLStreamReader xsr = xif.createXMLStreamReader(new StringReader(stringResponse));
			JAXBElement<?> element = m.unmarshal(xsr, payloadClazz);
			result = element.getValue();
		}

	    byte[] responseHash = null;
	    
	    try {
	    	responseHash = CryptoUtil.getEnvelopeHash(result);
	    } catch (NoSuchMethodException|IllegalAccessException|IllegalArgumentException|InvocationTargetException e) {
	    	// silently ignore if no ENVELOPE_HASH exist in class
	    }
	    
	    
		if (responseHash != null) {
			Matcher pm = CryptoUtil.BODY_REGEX.matcher(stringResponse);
			if (! pm.matches())
				new IllegalArgumentException();
			byte[] hash = DigestUtils.sha1(pm.group(CryptoUtil.BODY_GROUP).getBytes(CryptoUtil.UNICODE_CHARSET));
			
			boolean eq = Arrays.equals(hash, responseHash);
			if (! eq)
				throw new GeneralSecurityException("Mismatching Envelope Hash in message: "+stringResponse);
		}
	    return result;
	}
	
}
