package de.muenchen.refarch.integration.dms.fabasoft.mock.service.cases;

import com.fabasoft.schemas.websvc.lhmbai_15_1700_giwsd.CreateIncomingGI;
import com.fabasoft.schemas.websvc.lhmbai_15_1700_giwsd.CreateIncomingGIResponse;
import com.github.tomakehurst.wiremock.WireMockServer;
import de.muenchen.refarch.integration.dms.fabasoft.mock.WiremockWsdlUtility;
import org.springframework.stereotype.Component;

@Component
public class CreateIncomingDocumentCase implements MockCase {

    @Override
    public void initCase(final WireMockServer server) {

        final CreateIncomingGIResponse createIncomingGIResponse = new CreateIncomingGIResponse();
        createIncomingGIResponse.setObjid("1234567890");

        WiremockWsdlUtility.stubOperation(
                server,
                "CreateIncomingGI",
                CreateIncomingGI.class, (u) -> true,
                createIncomingGIResponse);

    }

}
