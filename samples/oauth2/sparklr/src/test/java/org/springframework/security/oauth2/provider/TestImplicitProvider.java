package org.springframework.security.oauth2.provider;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.net.URI;
import java.util.Arrays;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.test.BeforeOAuth2Context;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitResourceDetails;
import org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class TestImplicitProvider {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	@Rule
	public OAuth2ContextSetup context = OAuth2ContextSetup.standard(serverRunning);

	private String cookie;

	private String implicitUrl(String clientId) {
		URI uri = serverRunning.buildUri("/sparklr2/oauth/authorize").queryParam("response_type", "token")
				.queryParam("state", "mystateid").queryParam("client_id", clientId)
				.queryParam("redirect_uri", "http://anywhere").queryParam("scope", "read").build();
		return uri.toString();
	}

	@Test(expected = UserRedirectRequiredException.class)
	@OAuth2ContextConfiguration(resource = AutoApproveImplicit.class, initialize = false)
	public void testRedirectRequiredForAuthentication() throws Exception {
		context.getAccessToken();
	}

	@Test
	public void testBasicImplicitProvider() throws Exception {

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.TEXT_HTML));

		ResponseEntity<Void> result = serverRunning.getForResponse(implicitUrl("my-less-trusted-autoapprove-client"),
				headers);
		assertEquals(HttpStatus.FOUND, result.getStatusCode());
		String location = result.getHeaders().getLocation().toString();
		String cookie = result.getHeaders().getFirst("Set-Cookie");

		assertNotNull("Expected cookie in " + result.getHeaders(), cookie);
		headers.set("Cookie", cookie);

		ResponseEntity<String> response = serverRunning.getForString(location, headers);
		// should be directed to the login screen...
		assertTrue(response.getBody().contains("/login.do"));
		assertTrue(response.getBody().contains("username"));
		assertTrue(response.getBody().contains("password"));

		location = "/sparklr2/login.do";

		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("j_username", "marissa");
		formData.add("j_password", "koala");

		result = serverRunning.postForRedirect(location, headers, formData);

		// System.err.println(result.getStatusCode());
		// System.err.println(result.getHeaders());

		assertNotNull(result.getHeaders().getLocation());
		assertTrue(result.getHeaders().getLocation().toString().matches("http://anywhere#access_token=.+"));
	}


	@Test
	@OAuth2ContextConfiguration(resource = NonAutoApproveImplicit.class, initialize = false)
	public void testPostForNonAutomaticApprovalToken() throws Exception {

		context.getRestTemplate().getOAuth2ClientContext().getAccessTokenRequest().setCookie(cookie);
		try {
			context.getAccessToken();
			fail("Expected UserRedirectRequiredException");
		}
		catch (UserRedirectRequiredException e) {

			MultiValueMap<String, String> formData;
			HttpHeaders headers = new HttpHeaders();
			headers.set("Cookie", cookie);
			formData = new LinkedMultiValueMap<String, String>();
			formData.add(AuthorizationEndpoint.USER_OAUTH_APPROVAL, "true");
			ResponseEntity<Void> result = new RestTemplate().postForEntity(e.getRedirectUri(),
					new HttpEntity<MultiValueMap<String, String>>(formData, headers), Void.class);
			assertEquals(HttpStatus.FOUND, result.getStatusCode());

			String location = result.getHeaders().getLocation().toString();
			URI redirection = serverRunning.buildUri(location).build();
			assertEquals("anywhere", redirection.getHost());
			assertEquals("http", redirection.getScheme());

			// We've got the access token.
			String fragment = redirection.getFragment();
			assertNotNull("No fragment in redirect: " + redirection, fragment);

		}
	}

	@Test
	@OAuth2ContextConfiguration(resource = AutoApproveImplicit.class, initialize = false)
	public void testPostForAutomaticApprovalToken() throws Exception {
		context.getRestTemplate().getOAuth2ClientContext().getAccessTokenRequest().setCookie(cookie);
		assertNotNull(context.getAccessToken());
	}

	@BeforeOAuth2Context
	public void loginAndExtractCookie() {

		MultiValueMap<String, String> formData;
		formData = new LinkedMultiValueMap<String, String>();
		formData.add("j_username", "marissa");
		formData.add("j_password", "koala");

		String location = "/sparklr2/login.do";
		ResponseEntity<Void> result = serverRunning.postForStatus(location, formData);
		assertEquals(HttpStatus.FOUND, result.getStatusCode());
		String cookie = result.getHeaders().getFirst("Set-Cookie");

		assertNotNull("Expected cookie in " + result.getHeaders(), cookie);
		this.cookie = cookie;

	}

	static class AutoApproveImplicit extends ImplicitResourceDetails {
		public AutoApproveImplicit(Object target) {
			super();
			setClientId("my-less-trusted-autoapprove-client");
			setScope(Arrays.asList("read"));
			setId(getClientId());
			setPreEstablishedRedirectUri("http://anywhere");
			TestImplicitProvider test = (TestImplicitProvider) target;
			setAccessTokenUri(test.serverRunning.getUrl("/sparklr2/oauth/authorize"));
			setUserAuthorizationUri(test.serverRunning.getUrl("/sparklr2/oauth/authorize"));
		}
	}

	static class NonAutoApproveImplicit extends AutoApproveImplicit {
		public NonAutoApproveImplicit(Object target) {
			super(target);
			setClientId("my-less-trusted-client");
		}
	}

}
