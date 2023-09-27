package org.iru.rts.test;

import java.security.GeneralSecurityException;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Date;

import javax.xml.datatype.DatatypeConfigurationException;

import org.iru.rts.client.ReturnCode;
import org.iru.rts.client.classic.UploadClientImpl;
import org.iru.rts.safetirupload.Records;
import org.iru.rts.safetirupload.RequestReplyRecords;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import jakarta.xml.bind.JAXBException;
import org.junit.Assert;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = { "classpath:test.xml" })
public class TestUpload {

	@Autowired
	UploadClientImpl stuc;
	@Autowired
	Records.Record wsstRecord;
	@Autowired
	RequestReplyRecords.RequestReplyRecord wsreRecord;

	
	@Test
	public void wsst() throws JAXBException, GeneralSecurityException, DatatypeConfigurationException {
		ReturnCode rc = stuc.wsst(Collections.singletonList(wsstRecord), new SimpleDateFormat("yyyyMMddHHmmssZ").format(new Date()));
		Assert.assertEquals(2, rc.codeValue());
	}
	
	@Test
	public void wsre() throws JAXBException, GeneralSecurityException, DatatypeConfigurationException {
		ReturnCode rc = stuc.wsre(Collections.singletonList(wsreRecord), new SimpleDateFormat("yyyyMMddHHmmssZ").format(new Date()));
		Assert.assertEquals(2, rc.codeValue());
	}

	@Test
	public void wsstEmpty() throws JAXBException, GeneralSecurityException, DatatypeConfigurationException {
		ReturnCode rc = stuc.wsst(Collections.emptyList(), new SimpleDateFormat("yyyyMMddHHmmssZ").format(new Date()));
		Assert.assertEquals(2, rc.codeValue());
	}
	
	@Test
	public void wsreEmpty() throws JAXBException, GeneralSecurityException, DatatypeConfigurationException {
		ReturnCode rc = stuc.wsre(Collections.emptyList(), new SimpleDateFormat("yyyyMMddHHmmssZ").format(new Date()));
		Assert.assertEquals(2, rc.codeValue());
	}

}
