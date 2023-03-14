package org.iru.common.crypto.wscrypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.Charset;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.regex.Pattern;

import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.digest.DigestUtils;

public class CryptoUtil {

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

	public static byte[] getEnvelopeHash(Object obj) throws NoSuchMethodException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		if (obj == null) {
			throw new NoSuchMethodException("getEnvelope");
		}
		Method ge = obj.getClass().getMethod("getEnvelope");
		Object env = ge.invoke(obj);
		if (env != null) {
			Method gh = env.getClass().getMethod("getHash");
			Object hash = gh.invoke(env);
			if (hash == null || hash instanceof byte[]) {
				return (byte[]) hash;
			} else {
				throw new NoSuchMethodException("getHash");
			}
		} else {
			throw new NoSuchMethodException("getHash");
		}
	}

	public static void setEnvelopeHash(Object obj, byte[] hash) throws NoSuchMethodException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		if (obj == null) {
			throw new NoSuchMethodException("getEnvelope");
		}
		Method ge = obj.getClass().getMethod("getEnvelope");
		Object env = ge.invoke(obj);
		if (env != null) {
			Method sh = env.getClass().getMethod("setHash", byte[].class);
			sh.invoke(env, hash);
		} else {
			throw new NoSuchMethodException("setHash");
		}
	}

	
	static final IvParameterSpec IV_SPEC = new IvParameterSpec(new byte[] { 0x03, 0x01, 0x04, 0x01, 0x05, 0x09, 0x02, 0x06 });
	static final Charset UNICODE_CHARSET = Charset.forName("UTF-16LE");
	static final String RSA_CIPHER = "RSA/ECB/PKCS1Padding";
	static final String TRIPLE_DES_ALGO = "DESede";
	static final String TRIPLE_DES_CIPHER = "DESede/CBC/PKCS5Padding";
	static final Pattern BODY_REGEX = Pattern.compile(".*<(.+:)?Body>(.*)</(.+:)?Body>.*", Pattern.DOTALL);
	static final int BODY_GROUP = 2;
	
}
