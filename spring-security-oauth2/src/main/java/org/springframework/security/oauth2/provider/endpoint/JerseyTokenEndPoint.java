package org.springframework.security.oauth2.provider.endpoint;

import com.sun.jersey.spi.resource.Singleton;
import org.springframework.security.oauth2.common.DefaultOAuth2SerializationService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2SerializationService;
import org.springframework.security.oauth2.common.exceptions.UnsupportedGrantTypeException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.endpoint.params.OAuth2Parameters;

import javax.ws.rs.*;
import javax.ws.rs.core.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Singleton
@Path("/oauth/token")
public class JerseyTokenEndPoint extends JerseyAbstractEndPoint {

	private final OAuth2SerializationService serializationService = new DefaultOAuth2SerializationService();

	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Produces(MediaType.APPLICATION_JSON)
	public Response getAccessToken(@Context OAuth2Parameters oAuth2Parameters,
								   @Context HttpHeaders headers) {

		Map<String, String> parameters = oAuth2Parameters.getParameters();

		String[] clientValues = findClientSecret(headers, parameters);
		String clientId = clientValues[0];
		String clientSecret = clientValues[1];
		Set<String> scope = OAuth2Utils.parseScope(oAuth2Parameters.getScope());

		OAuth2AccessToken token = getTokenGranter().grant(oAuth2Parameters.getGrantType(), parameters, clientId, clientSecret, scope);
		if (token == null) {
			throw new UnsupportedGrantTypeException("Unsupported grant type: " + oAuth2Parameters.getGrantType());
		}

		return getResponse(token);

	}

	private Response getResponse(OAuth2AccessToken accessToken){

		String serializedToken = serializationService.serialize(accessToken);

		CacheControl cacheControl = new CacheControl();
		cacheControl.setNoStore(true);
		return Response.ok()
					   .cacheControl(cacheControl)
					   .type(MediaType.APPLICATION_JSON)
					   .entity(serializedToken)
					   .build();

	}

}
