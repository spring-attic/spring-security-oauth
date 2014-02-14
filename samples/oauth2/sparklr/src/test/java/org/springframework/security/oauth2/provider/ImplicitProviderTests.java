package org.springframework.security.oauth2.provider;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.test.BeforeOAuth2Context;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitResourceDetails;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class ImplicitProviderTests {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	@Rule
	public OAuth2ContextSetup context = OAuth2ContextSetup.standard(serverRunning);

	private String cookie;

	private HttpHeaders latestHeaders = null;

	@BeforeOAuth2Context
	public void loginAndExtractCookie() {

		ResponseEntity<String> page = serverRunning.getForString("/sparklr2/login.jsp");
		String cookie = page.getHeaders().getFirst("Set-Cookie");
		Matcher matcher = Pattern.compile("(?s).*name=\"_csrf\".*?value=\"([^\"]+).*").matcher(page.getBody());

		MultiValueMap<String, String> formData;
		formData = new LinkedMultiValueMap<String, String>();
		formData.add("j_username", "marissa");
		formData.add("j_password", "koala");
		if (matcher.matches()) {
			formData.add("_csrf", matcher.group(1));
		}

		String location = "/sparklr2/login.do";
		ResponseEntity<Void> result = serverRunning.postForStatus(location, formData);
		assertEquals(HttpStatus.FOUND, result.getStatusCode());
		cookie = result.getHeaders().getFirst("Set-Cookie");

		assertNotNull("Expected cookie in " + result.getHeaders(), cookie);
		this.cookie = cookie;

	}

	@Test(expected = UserRedirectRequiredException.class)
	@OAuth2ContextConfiguration(resource = AutoApproveImplicit.class, initialize = false)
	public void testRedirectRequiredForAuthentication() throws Exception {
		context.getAccessToken();
	}

	@Test
	@OAuth2ContextConfiguration(resource = AutoApproveImplicit.class, initialize = false)
	public void testPostForAutomaticApprovalToken() throws Exception {
		final ImplicitAccessTokenProvider implicitProvider = new ImplicitAccessTokenProvider();
		implicitProvider.setInterceptors(Arrays
				.<ClientHttpRequestInterceptor> asList(new ClientHttpRequestInterceptor() {
					public ClientHttpResponse intercept(HttpRequest request, byte[] body,
							ClientHttpRequestExecution execution) throws IOException {
						ClientHttpResponse result = execution.execute(request, body);
						latestHeaders = result.getHeaders();
						return result;
					}
				}));
		context.setAccessTokenProvider(implicitProvider);
		context.getAccessTokenRequest().setCookie(cookie);
		assertNotNull(context.getAccessToken());
		assertTrue("Wrong location header: " + latestHeaders.getLocation().getFragment(), latestHeaders.getLocation().getFragment()
				.contains("scope=read write trust"));
	}

	@Test
	@OAuth2ContextConfiguration(resource = NonAutoApproveImplicit.class, initialize = false)
	public void testPostForNonAutomaticApprovalToken() throws Exception {
		context.getAccessTokenRequest().setCookie(cookie);
		try {
			assertNotNull(context.getAccessToken());
			fail("Expected UserRedirectRequiredException");
		}
		catch (UserRedirectRequiredException e) {
			// ignore
		}
		// add user approval parameter for the second request
		context.getAccessTokenRequest().add(OAuth2Utils.USER_OAUTH_APPROVAL, "true");
		context.getAccessTokenRequest().add("scope.read", "true");
		assertNotNull(context.getAccessToken());
	}

	static class AutoApproveImplicit extends ImplicitResourceDetails {
		public AutoApproveImplicit(Object target) {
			super();
			setClientId("my-less-trusted-autoapprove-client");
			setId(getClientId());
			setPreEstablishedRedirectUri("http://anywhere");
			ImplicitProviderTests test = (ImplicitProviderTests) target;
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
