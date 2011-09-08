package org.springframework.security.oauth.examples.tonr;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.util.Collections;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.OAuth2SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2SecurityContextImpl;
import org.springframework.security.oauth2.client.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2SerializationService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class TestClientConnections {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();
	private AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();

	{
		resource.setAccessTokenUri(serverRunning.getUrl("/sparklr/oauth/authorize"));
		resource.setClientId("tonr");
		resource.setId("sparklr");
		resource.setUserAuthorizationUri(serverRunning.getUrl("/sparklr/oauth/user/authorize"));
	}

	@Test
	public void testCannotConnectWithoutToken() throws Exception {
		OAuth2RestTemplate template = new OAuth2RestTemplate(resource);
		try {
			template.getForObject(serverRunning.getUrl("/tonr/photos"), String.class);
			fail("Expected IllegalStateException");
		} catch (IllegalStateException e) {
			String message = e.getMessage();
			assertTrue("Wrong message: " + message,
					message.contains("No OAuth 2 security context has been established"));
		}
	}

	@Test
	public void testConnectWithToken() throws Exception {

		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "password");
		formData.add("client_id", "my-trusted-client");
		formData.add("scope", "read");
		formData.add("username", "marissa");
		formData.add("password", "koala");

		ResponseEntity<String> response = serverRunning.postForString("/sparklr/oauth/authorize", formData);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));

		DefaultOAuth2SerializationService serializationService = new DefaultOAuth2SerializationService();
		OAuth2AccessToken accessToken = serializationService.deserializeJsonAccessToken(new ByteArrayInputStream(
				response.getBody().getBytes()));

		OAuth2SecurityContextImpl context = new OAuth2SecurityContextImpl();
		context.setAccessTokens(Collections.singletonMap(resource.getId(), accessToken));
		OAuth2SecurityContextHolder.setContext(context);

		OAuth2RestTemplate template = new OAuth2RestTemplate(resource);
		String result = template.getForObject(serverRunning.getUrl("/sparklr/photos?format=xml"), String.class);
		// System.err.println(result);
		assertNotNull(result);

	}

}
