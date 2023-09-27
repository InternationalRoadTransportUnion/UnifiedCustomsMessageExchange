package org.iru.rtsplus.client.plus;

import java.util.Date;
import java.util.LinkedHashSet;
import java.util.Set;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;

import org.iru.rts.model.carnet_1.CarnetType;
import org.iru.rts.model.carnet_1.StoppedCarnetType;
import org.iru.rts.services.carnetservice_1.CarnetService;
import org.iru.rts.services.carnetservice_1.CarnetServiceSEI;
import org.iru.rts.services.carnetservice_1.StoppedCarnetsType;
import org.iru.rts.services.carnetservice_1.StoppedCarnetsType.StoppedCarnets;
import org.iru.rtsplus.client.CarnetServiceClient;

import jakarta.xml.ws.Holder;

public class CarnetServiceClientImpl extends AbstractWSSClient implements CarnetServiceClient {

	@Override
	public Set<StoppedCarnetType> getStoppedCarnets(Date from, Date to, Long retrievalRange) throws DatatypeConfigurationException {
		CarnetServiceSEI wsPort = getWsPort();
		
		XMLGregorianCalendar xFrom = convertToXML(from); 
		XMLGregorianCalendar xTo = convertToXML(to);
		
		Long range = retrievalRange;
		
		int offset = 0;
		Set<StoppedCarnetType> stoppedCarnets = new LinkedHashSet<StoppedCarnetType>();
		while (true) {
	        
	        Holder<org.iru.rts.services.carnetservice_1.StoppedCarnetsType.Total> totalHolder = new Holder<StoppedCarnetsType.Total>();
	        Holder<org.iru.rts.services.carnetservice_1.StoppedCarnetsType.StoppedCarnets> stoppedCarnetsHolder = new Holder<org.iru.rts.services.carnetservice_1.StoppedCarnetsType.StoppedCarnets>();
			
			wsPort.getStoppedCarnets(xFrom, xTo, offset, range, totalHolder, stoppedCarnetsHolder);
			StoppedCarnets data = stoppedCarnetsHolder.value;
			stoppedCarnets.addAll(data.getStoppedCarnet());
			range = (long) data.getCount();
			if (data.isEndReached())
				break;
			else
				offset = data.getOffset()+data.getCount();
		}
		return stoppedCarnets;
	}

	protected QName getServiceQName() {
		return new QName("http://rts.iru.org/services/CarnetService-1", "CarnetService");
	}
	
	protected QName getPortQName() {
		return new QName("http://rts.iru.org/services/CarnetService-1", "CarnetServicePort"+portNameSuffix);
	}
	
	protected CarnetServiceSEI getWsPort() {
		return getWsPort(CarnetService.class, CarnetServiceSEI.class);
	}
	
	@Override
	public CarnetType queryCarnet(String tirCarnetNumber) {
		CarnetServiceSEI wsPort = getWsPort();
		return wsPort.queryCarnet(tirCarnetNumber);
	}
	
}
