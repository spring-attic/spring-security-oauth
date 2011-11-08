package org.springframework.security.oauth.examples.tonr;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.net.URLEncoder;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.context.OAuth2ClientContext;
import org.springframework.security.oauth2.client.context.OAuth2ClientContextHolder;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

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
		resource.setScope(Arrays.asList("trust"));
		resource.setUserAuthorizationUri(serverRunning.getUrl("/sparklr/oauth/authorize"));
	}

	@After
	public void close() {
		OAuth2ClientContextHolder.clearContext();
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

		OAuth2ClientContext context = new OAuth2ClientContext();
		OAuth2ClientContextHolder.setContext(context);
		
		ClientCredentialsResourceDetails resource = new ClientCredentialsResourceDetails();

		resource.setAccessTokenUri(serverRunning.getUrl("/sparklr/oauth/token"));
		resource.setClientId("my-client-with-registered-redirect");
		resource.setId("sparklr");
		resource.setScope(Arrays.asList("trust"));

		ClientCredentialsAccessTokenProvider provider = new ClientCredentialsAccessTokenProvider();
		OAuth2AccessToken accessToken = provider.obtainNewAccessToken(resource, new AccessTokenRequest());
		context.setAccessTokens(Collections.singletonMap(resource.getId(), accessToken));

		// TODO: should this work? The client id is different.
		OAuth2RestTemplate template = new OAuth2RestTemplate(resource);
		String result = template.getForObject(serverRunning.getUrl("/sparklr/trusted/message"), String.class);
		// System.err.println(result);
		assertNotNull(result);

	}

	@Test
	public void testConnectWithAutomaticToken() throws Exception {

		// tonr is a trusted client of sparklr for this resource
		RestTemplate template = new RestTemplate();
		String result = template.getForObject(serverRunning.getUrl("/tonr/trusted/message"), String.class);
		// System.err.println(result);
		assertNotNull(result);

	}

	@Test
	public void testAttemptedTokenAcquisitionWithNoContext() throws Exception {
		AuthorizationCodeAccessTokenProvider provider = new AuthorizationCodeAccessTokenProvider();
		try {
			OAuth2AccessToken token = provider.obtainNewAccessToken(resource, new AccessTokenRequest());
			fail("Expected IllegalStateException");
			assertNotNull(token);
		} catch (IllegalStateException e) {
			String message = e.getMessage();
			assertTrue("Wrong message: " + message,
					message.contains("No redirect URI has been established"));
		}
	}

	@Test
	public void testAttemptedTokenAcquisitionWithWrongContext() throws Exception {
		OAuth2ClientContextHolder.setContext(new OAuth2ClientContext());
		AuthorizationCodeAccessTokenProvider provider = new AuthorizationCodeAccessTokenProvider();
		try {
			OAuth2AccessToken token = provider.obtainNewAccessToken(resource, new AccessTokenRequest());
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

		OAuth2ClientContext context = new OAuth2ClientContext();
		OAuth2ClientContextHolder.setContext(context);
		AuthorizationCodeAccessTokenProvider provider = new AuthorizationCodeAccessTokenProvider();

		Map<String, String> requestParams = new HashMap<String, String>();
		String uri = null;
		AccessTokenRequest accessTokenRequest = new AccessTokenRequest();
		try {
			OAuth2AccessToken token = provider.obtainNewAccessToken(resource, accessTokenRequest);
			fail("Expected UserRedirectRequiredException");
			assertNotNull(token);
		} catch (UserRedirectRequiredException e) {

			requestParams = e.getRequestParams();
			uri = e.getRedirectUri();
			assertEquals("Wrong uri: " + uri, resource.getUserAuthorizationUri(), uri);

		}

		assertNotNull(requestParams);
		// If redirect URI is registered there should be some state
		assertTrue("Wrong request params: " + requestParams, requestParams.containsKey("state"));

		// This would be done by the ClientContextFilter. TODO: extract into a strategy?
		StringBuilder builder = new StringBuilder(uri);
		char appendChar = uri.indexOf('?') < 0 ? '?' : '&';
		for (Map.Entry<String, String> param : requestParams.entrySet()) {
			builder.append(appendChar).append(param.getKey()).append('=')
					.append(URLEncoder.encode(param.getValue(), "UTF-8"));
			appendChar = '&';
		}
		assertEquals(HttpStatus.OK, serverRunning.getStatusCode(builder.toString(), headers));

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
		accessTokenRequest.setAuthorizationCode(code);
		// TODO: unhack the state (should be autogenerated)
		accessTokenRequest.setPreservedState("foo");
		OAuth2AccessToken token = provider.obtainNewAccessToken(resource, accessTokenRequest);
		assertNotNull(token);

	}

	private String extractParameter(String location, String key) {
		location = location.substring(location.indexOf("?") + 1);
		for (String query : location.split("&")) {
			String[] keyValue = query.split("=");
			if (keyValue[0].equals(key)) {
				return keyValue[1];
			}
		}
		return null;
	}

}
