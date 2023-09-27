package org.iru.rts.client;

import java.io.IOException;
import java.security.GeneralSecurityException;

import jakarta.xml.bind.JAXBException;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.stream.XMLStreamException;

public interface EGISClient {

	public EGISResponse queryCarnet(String carnetNumber, String queryID) throws DatatypeConfigurationException, IOException, JAXBException, GeneralSecurityException, XMLStreamException;
}
