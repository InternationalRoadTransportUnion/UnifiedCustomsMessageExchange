package org.iru.rts.test;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.stream.XMLStreamException;

import org.iru.rts.client.EGISResponse;
import org.iru.rts.client.classic.EGISClientImpl;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import jakarta.xml.bind.JAXBException;
import junit.framework.Assert;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = { "classpath:test.xml" })
public class TestEGIS {

	@Autowired
	private EGISClientImpl egis;

	public static class Carnet {
		private String number;

		public void setNumber(String number) {
			this.number = number;
		}

		public void setResult(int result) {
			this.result = result;
		}

		private int result;
	}

	@Autowired
	private Carnet carnet;

	@Test
	public void queryInvalidCarnet() throws DatatypeConfigurationException, IOException, JAXBException,
			GeneralSecurityException, XMLStreamException {
		
		EGISResponse response = egis.queryCarnet(carnet.number, new SimpleDateFormat("yyyyMMddHHmmssZ").format(new Date()));

		Assert.assertEquals(carnet.result, response.getResult());
		Assert.assertEquals(carnet.number, response.getCarnetNumber());
		if (carnet.result == 5) { 
			Assert.assertNull(response.getAssociation());
			Assert.assertNull(response.getHolderID());
			Assert.assertNull(response.getNumTerminations());
			Assert.assertNull(response.getValidityDate());
		}
		Assert.assertEquals(carnet.number, response.getRequestedGuaranteeNumber());
	}
	
}
