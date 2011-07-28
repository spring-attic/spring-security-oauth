package org.springframework.security.oauth2.provider;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

import java.util.List;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.NewCookie;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.security.oauth2.common.DefaultOAuth2SerializationService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.core.util.MultivaluedMapImpl;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class TestNativeApplicationProfile {
	
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
	}

	/**
	 * tests a happy-day flow of the native application profile.
	 */
	@Test
	public void testSecretRequired() throws Exception {

		Client client = Client.create();
		client.setFollowRedirects(false);

		MultivaluedMap<String, String> formData = new MultivaluedMapImpl();
		formData.add("grant_type", "password");
		formData.add("client_id", "my-trusted-client-with-secret");
		formData.add("username", "marissa");
		formData.add("password", "koala");
		ClientResponse response = client.resource(serverRunning.getUrl("/sparklr/oauth/authorize"))
				.type(MediaType.APPLICATION_FORM_URLENCODED_TYPE).post(ClientResponse.class, formData);
		assertEquals(401, response.getClientResponseStatus().getStatusCode());

		formData = new MultivaluedMapImpl();
		formData.add("grant_type", "password");
		formData.add("client_id", "my-trusted-client-with-secret");
		formData.add("client_secret", "somesecret");
		formData.add("username", "marissa");
		formData.add("password", "koala");
		response = client.resource(serverRunning.getUrl("/sparklr/oauth/authorize"))
				.type(MediaType.APPLICATION_FORM_URLENCODED_TYPE).post(ClientResponse.class, formData);
		assertEquals(200, response.getClientResponseStatus().getStatusCode());
	}

	/**
	 * tests that an error occurs if you attempt to use username/password creds for a non-password grant type.
	 */
	@Test
	public void testInvalidGrantType() throws Exception {

		Client client = Client.create();
		client.setFollowRedirects(false);

		MultivaluedMap<String, String> formData = new MultivaluedMapImpl();
		formData.add("grant_type", "authorization_code");
		formData.add("client_id", "my-trusted-client");
		formData.add("username", "marissa");
		formData.add("password", "koala");
		ClientResponse response = client.resource(serverRunning.getUrl("/sparklr/oauth/authorize"))
				.type(MediaType.APPLICATION_FORM_URLENCODED_TYPE).post(ClientResponse.class, formData);
		assertEquals(400, response.getClientResponseStatus().getStatusCode());
		List<NewCookie> newCookies = response.getCookies();
		if (!newCookies.isEmpty()) {
			fail("No cookies should be set. Found: " + newCookies.get(0).getName() + ".");
		}
		assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));

		DefaultOAuth2SerializationService serializationService = new DefaultOAuth2SerializationService();
		try {
			throw serializationService.deserializeJsonError(response.getEntityInputStream());
		} catch (OAuth2Exception e) {
			assertEquals("invalid_request", e.getOAuth2ErrorCode());
		}
	}

	/**
	 * tests a happy-day flow of the native application profile.
	 */
	@Test
	public void testClientRoleBasedSecurity() throws Exception {

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
		response = client.resource(serverRunning.getUrl("/sparklr/trusted/message")).get(ClientResponse.class);
		assertFalse(200 == response.getClientResponseStatus().getStatusCode());

		// now make sure an authorized request is valid.
		response = client.resource(serverRunning.getUrl("/sparklr/trusted/message"))
				.header("Authorization", String.format("OAuth2 %s", accessToken.getValue())).get(ClientResponse.class);
		assertEquals(200, response.getClientResponseStatus().getStatusCode());
	}

}
