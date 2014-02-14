package org.springframework.security.oauth.examples.tonr;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class TestAuthorizationCodeGrant {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	private AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();

	{
		resource.setAccessTokenUri(serverRunning
				.getUrl("/sparklr2/oauth/token"));
		resource.setClientId("my-client-with-registered-redirect");
		resource.setId("sparklr");
		resource.setScope(Arrays.asList("trust"));
		resource.setUserAuthorizationUri(serverRunning
				.getUrl("/sparklr2/oauth/authorize"));
	}

	@Test
	public void testCannotConnectWithoutToken() throws Exception {

		OAuth2RestTemplate template = new OAuth2RestTemplate(resource);
		resource.setPreEstablishedRedirectUri("http://anywhere.com");
		try {
			template.getForObject(serverRunning.getUrl("/tonr2/photos"),
					String.class);
			fail("Expected UserRedirectRequiredException");
		} catch (UserRedirectRequiredException e) {
			String message = e.getMessage();
			assertTrue(
					"Wrong message: " + message,
					message.contains("A redirect is required to get the users approval"));
		}
	}

	@Test
	public void testAttemptedTokenAcquisitionWithNoRedirect() throws Exception {
		AuthorizationCodeAccessTokenProvider provider = new AuthorizationCodeAccessTokenProvider();
		try {
			OAuth2AccessToken token = provider.obtainAccessToken(resource,
					new DefaultAccessTokenRequest());
			fail("Expected UserRedirectRequiredException");
			assertNotNull(token);
		} catch (UserRedirectRequiredException e) {
			String message = e.getMessage();
			assertTrue("Wrong message: " + message,
					message.contains("A redirect is required"));
		}
	}

	@Test
	public void testTokenAcquisitionWithCorrectContext() throws Exception {

		ResponseEntity<String> page = serverRunning.getForString("/tonr2/login.jsp");
		String cookie = page.getHeaders().getFirst("Set-Cookie");
		HttpHeaders headers = new HttpHeaders();
		headers.set("Cookie", cookie);
		Matcher matcher = Pattern.compile("(?s).*name=\"_csrf\".*?value=\"([^\"]+).*").matcher(page.getBody());

		MultiValueMap<String, String> form;
		form = new LinkedMultiValueMap<String, String>();
		form.add("j_username", "marissa");
		form.add("j_password", "wombat");
		if (matcher.matches()) {
			form.add("_csrf", matcher.group(1));
		}
		ResponseEntity<Void> response = serverRunning.postForStatus("/tonr2/login.do", headers, 
				form);
		cookie = response.getHeaders().getFirst("Set-Cookie");

		headers = new HttpHeaders();
		headers.set("Cookie", cookie);
		// headers.setAccept(Collections.singletonList(MediaType.ALL));
		headers.setAccept(MediaType
				.parseMediaTypes("image/png,image/*;q=0.8,*/*;q=0.5"));

		String location = serverRunning.getForRedirect(
				"/tonr2/sparklr/photos/1", headers);
		location = authenticateAndApprove(location);

		assertTrue("Redirect location should be to the original photo URL: "
				+ location, location.contains("photos/1"));
		HttpStatus status = serverRunning.getStatusCode(location, headers);
		assertEquals(HttpStatus.OK, status);
	}

	@Test
	public void testTokenAcquisitionWithRegisteredRedirect() throws Exception {

		ResponseEntity<String> page = serverRunning.getForString("/tonr2/login.jsp");
		String cookie = page.getHeaders().getFirst("Set-Cookie");
		HttpHeaders headers = new HttpHeaders();
		headers.set("Cookie", cookie);
		Matcher matcher = Pattern.compile("(?s).*name=\"_csrf\".*?value=\"([^\"]+).*").matcher(page.getBody());

		MultiValueMap<String, String> form;
		form = new LinkedMultiValueMap<String, String>();
		form.add("j_username", "marissa");
		form.add("j_password", "wombat");
		if (matcher.matches()) {
			form.add("_csrf", matcher.group(1));
		}
		ResponseEntity<Void> response = serverRunning.postForStatus("/tonr2/login.do", headers, 
				form);
		cookie = response.getHeaders().getFirst("Set-Cookie");

		headers = new HttpHeaders();
		headers.set("Cookie", cookie);

		// The registered redirect is /redirect, but /trigger is used as a test
		// because it is different (i.e. not the current request URI).
		String location = serverRunning.getForRedirect(
				"/tonr2/sparklr/trigger", headers);
		location = authenticateAndApprove(location);

		assertTrue("Redirect location should be to the original photo URL: "
				+ location, location.contains("sparklr/redirect"));
		HttpStatus status = serverRunning.getStatusCode(location, headers);
		assertEquals(HttpStatus.OK, status);
	}

	private String authenticateAndApprove(String location) {

		ResponseEntity<String> page = serverRunning.getForString("/sparklr2/login.jsp");
		String cookie = page.getHeaders().getFirst("Set-Cookie");
		Matcher matcher = Pattern.compile("(?s).*name=\"_csrf\".*?value=\"([^\"]+).*").matcher(page.getBody());

		MultiValueMap<String, String> form;
		form = new LinkedMultiValueMap<String, String>();
		form.add("j_username", "marissa");
		form.add("j_password", "koala");
		if (matcher.matches()) {
			form.add("_csrf", matcher.group(1));
		}

		HttpHeaders response = serverRunning.postForHeaders(
				"/sparklr2/login.do", form);

		cookie = response.getFirst("Set-Cookie");
		HttpHeaders headers = new HttpHeaders();
		headers.set("Cookie", cookie);

		serverRunning.getForString(location, headers);
		// Should be on user approval page now
		form = new LinkedMultiValueMap<String, String>();
		form.add("user_oauth_approval", "true");
		form.add("scope.read", "true");
		response = serverRunning.postForHeaders("/sparklr2/oauth/authorize",
				form, headers);

		return response.getLocation().toString();
	}

}
