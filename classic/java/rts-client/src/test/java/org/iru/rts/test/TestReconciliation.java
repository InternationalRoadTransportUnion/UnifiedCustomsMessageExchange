package org.iru.rts.test;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

import javax.xml.bind.JAXBException;
import javax.xml.datatype.DatatypeConfigurationException;

import org.iru.rts.client.ReconciliationClient;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = { "classpath:test.xml" })
public class TestReconciliation {

	@Autowired
	private ReconciliationClient wsrq;
	 
	@Test
	public void wsrq() throws JAXBException, GeneralSecurityException, IOException, DatatypeConfigurationException {
		List<?> list = wsrq.downloadReconciliationRequests(new SimpleDateFormat("yyyyMMddHHmmssZ").format(new Date()));
		Assert.assertEquals(0, list.size());
	}
	
}
