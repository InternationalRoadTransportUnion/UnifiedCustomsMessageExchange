package org.iru.rts.client;

import java.io.IOException;
import java.security.GeneralSecurityException;

import jakarta.xml.bind.JAXBException;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.stream.XMLStreamException;

public interface HolderQueryClient {

	public HolderQueryResponse queryCarnet(String carnetNumber, String queryID, HolderQueryReason reason) throws DatatypeConfigurationException, IOException, JAXBException, GeneralSecurityException, XMLStreamException;
}
