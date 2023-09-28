package org.iru.rts.test;

import java.util.GregorianCalendar;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

public class XmlUtils {

	public static XMLGregorianCalendar newXMLGregorianCalendar(int year, int month, int dayOfMonth) throws DatatypeConfigurationException {
		return DatatypeFactory.newInstance().newXMLGregorianCalendar(new GregorianCalendar(year, month, dayOfMonth));
	}
	
}
