package org.springframework.security.oauth2.provider.endpoint;

import com.sun.jersey.spi.resource.Singleton;
import org.springframework.security.oauth2.common.DefaultOAuth2SerializationService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2SerializationService;
import org.springframework.security.oauth2.common.exceptions.UnsupportedGrantTypeException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;

import javax.ws.rs.*;
import javax.ws.rs.core.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Singleton
@Path("/oauth/token")
public class JerseyTokenEndPoint extends JerseyAbstractEndPoint {

	private String defaultGrantType = "authorization_code";

	private final OAuth2SerializationService serializationService = new DefaultOAuth2SerializationService();

	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Produces(MediaType.APPLICATION_JSON)
	public Response getAccessToken(@FormParam("grant_type") String grantType,
								   @FormParam("client_secret") String clientSecretParam,
								   @FormParam("client_id") String clientIdParam,
								   @FormParam("scope") String scopeParam,
							   	   @FormParam("username") String userName,
								   @FormParam("password") String password,
								   @Context HttpHeaders headers) {

		if(null == grantType){
			grantType = defaultGrantType;
		}

		Map<String, String> parameters = new HashMap<String, String>();
		parameters.put("client_secret", clientSecretParam);
		parameters.put("client_id", clientIdParam);
		parameters.put("scope", scopeParam);
		parameters.put("username", userName);
		parameters.put("password", password);

		String[] clientValues = findClientSecret(headers, parameters);
		String clientId = clientValues[0];
		String clientSecret = clientValues[1];
		Set<String> scope = OAuth2Utils.parseScope(scopeParam);

		OAuth2AccessToken token = getTokenGranter().grant(grantType, parameters, clientId, clientSecret, scope);
		if (token == null) {
			throw new UnsupportedGrantTypeException("Unsupported grant type: " + grantType);
		}

		return getResponse(token);

	}

	private Response getResponse(OAuth2AccessToken accessToken){

		String serializedToken = serializationService.serialize(accessToken);

		CacheControl cacheControl = new CacheControl();
		cacheControl.setNoStore(true);
		Response response = Response.ok()
				                    .cacheControl(cacheControl)
									.type(MediaType.APPLICATION_JSON)
								    .entity(serializedToken)
				                    .build();
		return response;

	}

	public void setDefaultGrantType(String defaultGrantType) {
		this.defaultGrantType = defaultGrantType;
	}

}
