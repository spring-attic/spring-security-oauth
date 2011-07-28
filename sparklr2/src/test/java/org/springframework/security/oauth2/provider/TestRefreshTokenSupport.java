package org.springframework.security.oauth2.provider;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.security.oauth2.common.DefaultOAuth2SerializationService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.core.util.MultivaluedMapImpl;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class TestRefreshTokenSupport {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	/**
	 * tests a happy-day flow of the native application profile.
	 */
	@Test
	public void testHappyDay() throws Exception {

		Client client = Client.create();
		client.setFollowRedirects(false);

		MultivaluedMap<String, String> formData = new MultivaluedMapImpl();
		formData.add("grant_type", "password");
		formData.add("client_id", "my-trusted-client");
		formData.add("username", "marissa");
		formData.add("password", "koala");
		ClientResponse response = client.resource(serverRunning.getUrl("/sparklr/oauth/authorize"))
				.type(MediaType.APPLICATION_FORM_URLENCODED_TYPE).post(ClientResponse.class, formData);
		assertEquals(200, response.getClientResponseStatus().getStatusCode());
		assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));

		DefaultOAuth2SerializationService serializationService = new DefaultOAuth2SerializationService();
		OAuth2AccessToken accessToken = serializationService
				.deserializeJsonAccessToken(response.getEntityInputStream());

		// now try and use the token to access a protected resource.

		// first make sure the resource is actually protected.
		response = client.resource(serverRunning.getUrl("/sparklr/photos?format=json")).get(ClientResponse.class);
		assertFalse(200 == response.getClientResponseStatus().getStatusCode());

		// now make sure an authorized request is valid.
		response = client.resource(serverRunning.getUrl("/sparklr/photos?format=json"))
				.header("Authorization", String.format("OAuth2 %s", accessToken.getValue())).get(ClientResponse.class);
		assertEquals(200, response.getClientResponseStatus().getStatusCode());

		// now use the refresh token to get a new access token.
		assertNotNull(accessToken.getRefreshToken());
		formData = new MultivaluedMapImpl();
		formData.add("grant_type", "refresh_token");
		formData.add("client_id", "my-trusted-client");
		formData.add("refresh_token", accessToken.getRefreshToken().getValue());
		response = client.resource(serverRunning.getUrl("/sparklr/oauth/authorize"))
				.type(MediaType.APPLICATION_FORM_URLENCODED_TYPE).post(ClientResponse.class, formData);
		assertEquals(200, response.getClientResponseStatus().getStatusCode());
		assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));
		OAuth2AccessToken newAccessToken = serializationService.deserializeJsonAccessToken(response
				.getEntityInputStream());
		assertFalse(newAccessToken.getValue().equals(accessToken.getValue()));

		// make sure the new access token can be used.
		response = client.resource(serverRunning.getUrl("/sparklr/photos?format=json"))
				.header("Authorization", String.format("OAuth2 %s", newAccessToken.getValue()))
				.get(ClientResponse.class);
		assertEquals(200, response.getClientResponseStatus().getStatusCode());

		// make sure the old access token isn't valid anymore.
		response = client.resource(serverRunning.getUrl("/sparklr/photos?format=json"))
				.header("Authorization", String.format("OAuth2 %s", accessToken.getValue())).get(ClientResponse.class);
		assertEquals(401, response.getClientResponseStatus().getStatusCode());
	}
}
