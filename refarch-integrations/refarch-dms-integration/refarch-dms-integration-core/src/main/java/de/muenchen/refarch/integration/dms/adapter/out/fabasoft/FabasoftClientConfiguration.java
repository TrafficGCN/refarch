package de.muenchen.refarch.integration.dms.adapter.out.fabasoft;

import com.fabasoft.schemas.websvc.lhmbai_15_1700_giwsd.LHMBAI151700GIWSD;
import com.fabasoft.schemas.websvc.lhmbai_15_1700_giwsd.LHMBAI151700GIWSDSoap;
import jakarta.xml.ws.BindingProvider;
import jakarta.xml.ws.soap.SOAPBinding;
import lombok.RequiredArgsConstructor;

/**
 * Configuration of the Webservice Client.
 */
@RequiredArgsConstructor
public class FabasoftClientConfiguration {

    private final FabasoftProperties properties;

    public LHMBAI151700GIWSDSoap dmsWsClient() {
        final LHMBAI151700GIWSD service = new LHMBAI151700GIWSD();
        final LHMBAI151700GIWSDSoap soapClient = service.getLHMBAI151700GIWSDSoap();
        ((BindingProvider) soapClient).getRequestContext().put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, this.properties.getUrl());
        ((BindingProvider) soapClient).getRequestContext().put(BindingProvider.USERNAME_PROPERTY, this.properties.getUsername());
        ((BindingProvider) soapClient).getRequestContext().put(BindingProvider.PASSWORD_PROPERTY, this.properties.getPassword());
        if (properties.getEnableMtom()) {
            final SOAPBinding binding = (SOAPBinding) ((BindingProvider) soapClient).getBinding();
            binding.setMTOMEnabled(true);
        }
        return soapClient;
    }
}
