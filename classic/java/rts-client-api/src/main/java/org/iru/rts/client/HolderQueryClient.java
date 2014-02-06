package org.iru.rts.client;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.xml.bind.JAXBException;
import javax.xml.datatype.DatatypeConfigurationException;

public interface HolderQueryClient {

	public HolderQueryResponse queryCarnet(String carnetNumber, String queryID, HolderQueryReason reason) throws DatatypeConfigurationException, IOException, JAXBException, GeneralSecurityException;
}
