package org.springframework.security.oauth.examples.tonr;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.net.URLEncoder;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.OAuth2SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2SecurityContextImpl;
import org.springframework.security.oauth2.client.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.code.AuthorizationCodeAccessTokenProvider;
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
		resource.setAccessTokenUri(serverRunning.getUrl("/sparklr/oauth/token"));
		resource.setClientId("my-client-with-registered-redirect");
		resource.setId("sparklr");
		resource.setUserAuthorizationUri(serverRunning.getUrl("/sparklr/oauth/authorize"));
	}

	@After
	public void close() {
		OAuth2SecurityContextHolder.setContext(null);
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

		// TODO: should this work?  The client id is different.
		OAuth2RestTemplate template = new OAuth2RestTemplate(resource);
		String result = template.getForObject(serverRunning.getUrl("/sparklr/photos?format=xml"), String.class);
		// System.err.println(result);
		assertNotNull(result);

	}

	@Test
	public void testAttemptedTokenAcquisitionWithNoContext() throws Exception {
		AuthorizationCodeAccessTokenProvider provider = new AuthorizationCodeAccessTokenProvider();
		try {
			OAuth2AccessToken token = provider.obtainNewAccessToken(resource);
			fail("Expected IllegalStateException");
			assertNotNull(token);
		} catch (IllegalStateException e) {
			String message = e.getMessage();
			assertTrue("Wrong message: " + message,
					message.contains("No OAuth 2 security context has been established"));
		}
	}

	@Test
	public void testAttemptedTokenAcquisitionWithWrongContext() throws Exception {
		OAuth2SecurityContextHolder.setContext(new OAuth2SecurityContextImpl());
		AuthorizationCodeAccessTokenProvider provider = new AuthorizationCodeAccessTokenProvider();
		try {
			OAuth2AccessToken token = provider.obtainNewAccessToken(resource);
			fail("Expected IllegalStateException");
			assertNotNull(token);
		} catch (IllegalStateException e) {
			String message = e.getMessage();
			assertTrue("Wrong message: " + message, message.contains("No redirect URI has been established"));
		}
	}

	/**
	 * @throws Exception
	 */
	@Test
	public void testTokenAcquisitionWithCorrectContext() throws Exception {

		// First authenticate and grab the cookie
		MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>();
		form.add("j_username", "marissa");
		form.add("j_password", "koala");
		HttpHeaders response = serverRunning.postForHeaders("/sparklr/login.do", form);

		String cookie = response.getFirst("Set-Cookie");
		HttpHeaders headers = new HttpHeaders();
		headers.set("Cookie", cookie);

		resource.setPreEstablishedRedirectUri("http://anywhere");
		resource.setState("foo");

		OAuth2SecurityContextImpl context = new OAuth2SecurityContextImpl();
		OAuth2SecurityContextHolder.setContext(context);
		AuthorizationCodeAccessTokenProvider provider = new AuthorizationCodeAccessTokenProvider();

		Map<String, String> requestParams = new HashMap<String, String>();
		String uri = null;
		try {
			OAuth2AccessToken token = provider.obtainNewAccessToken(resource);
			fail("Expected UserRedirectRequiredException");
			assertNotNull(token);
		} catch (UserRedirectRequiredException e) {

			requestParams = e.getRequestParams();
			uri = e.getRedirectUri();
			assertEquals("Wrong uri: " + uri, resource.getUserAuthorizationUri(), uri);

		}
		
		assertNotNull(requestParams);
		// If redirect URI is registered there should be some state
		assertTrue("Wrong request params: "+requestParams, requestParams.containsKey("state"));

		// This would be done by the ClientContextFilter. TODO: extract into a strategy?
		StringBuilder builder = new StringBuilder(uri);
		char appendChar = uri.indexOf('?') < 0 ? '?' : '&';
		for (Map.Entry<String, String> param : requestParams.entrySet()) {
			builder.append(appendChar).append(param.getKey()).append('=')
					.append(URLEncoder.encode(param.getValue(), "UTF-8"));
			appendChar = '&';
		}
		assertEquals(HttpStatus.FOUND, serverRunning.getStatusCode(builder.toString(), headers));

		form = new LinkedMultiValueMap<String, String>();
		form.add("user_oauth_approval", "true");
		form.add("redirect_uri", resource.getPreEstablishedRedirectUri());
		// TODO: if redirect_uri is not supplied we should get a 400, not a 302
		response = serverRunning.postForHeaders(resource.getUserAuthorizationUri(), form, headers);

		String location = response.getFirst("Location");
		assertTrue("Wrong location: " + location, location.startsWith("http://anywhere"));
		
		System.err.println(location);
		String code = extractParameter(location, "code");
		assertNotNull(code);
		
		// Now the access token can be retrieved...
		context.setAuthorizationCode(code);
		// TODO: unhack the state (should be autogenerated)
		context.setPreservedState("foo");
		OAuth2AccessToken token = provider.obtainNewAccessToken(resource);
		assertNotNull(token);

	}

	public String extractParameter(String location, String key) {
		location = location.substring(location.indexOf("?")+1);
		for (String query : location.split("&")) {
			String[] keyValue = query.split("=");
			if (keyValue[0].equals(key)) {
				return keyValue[1];
			}
		}
		return null;
	}

}
