package org.iru.rtsplus.test;

import java.util.Date;
import java.util.Set;

import org.iru.rts.model.carnet_1.StoppedCarnetType;
import org.iru.rtsplus.client.plus.CarnetServiceClientImpl;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.Assert;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = { "classpath:wstest.xml" })
public class TestCarnetService {
	
	@Autowired
	CarnetServiceClientImpl carn;
	
	@Test
	public void listLastYearInvalidatedCarnets() throws Exception {
		long now = System.currentTimeMillis();
		System.setProperty("com.sun.xml.ws.transport.http.client.HttpTransportPipe.dump", "true");

		org.apache.xml.security.Init.init();
		
		Date lastYear = new Date(now - 150L*24L*3600000L);
		Set<StoppedCarnetType> stopped = carn.getStoppedCarnets(lastYear, new Date(now), null);
		System.out.println(stopped.size());
		Assert.notEmpty(stopped);
	}
}
