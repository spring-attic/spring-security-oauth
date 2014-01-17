package org.springframework.security.oauth2.provider;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.List;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.client.test.BeforeOAuth2Context;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.ResponseExtractor;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class TestResourceOwnerPasswordProvider {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	@Rule
	public OAuth2ContextSetup context = OAuth2ContextSetup.standard(serverRunning);

	private ClientHttpResponse tokenEndpointResponse;

	@BeforeOAuth2Context
	public void setupAccessTokenProvider() {
		ResourceOwnerPasswordAccessTokenProvider accessTokenProvider = new ResourceOwnerPasswordAccessTokenProvider() {

			private ResponseExtractor<OAuth2AccessToken> extractor = super.getResponseExtractor();

			private ResponseErrorHandler errorHandler = super.getResponseErrorHandler();

			@Override
			protected ResponseErrorHandler getResponseErrorHandler() {
				return new DefaultResponseErrorHandler() {
					public void handleError(ClientHttpResponse response) throws IOException {
						response.getHeaders();
						response.getStatusCode();
						tokenEndpointResponse = response;
						errorHandler.handleError(response);
					}
				};
			}

			@Override
			protected ResponseExtractor<OAuth2AccessToken> getResponseExtractor() {
				return new ResponseExtractor<OAuth2AccessToken>() {

					public OAuth2AccessToken extractData(ClientHttpResponse response) throws IOException {
						response.getHeaders();
						response.getStatusCode();
						tokenEndpointResponse = response;
						return extractor.extractData(response);
					}

				};
			}
		};
		context.setAccessTokenProvider(accessTokenProvider);
	}

	@Test
	public void testUnauthenticated() throws Exception {
		// first make sure the resource is actually protected.
		assertEquals(HttpStatus.UNAUTHORIZED, serverRunning.getStatusCode("/sparklr2/photos?format=json"));
	}

	@Test
	public void testUnauthenticatedErrorMessage() throws Exception {
		HttpHeaders headers = new HttpHeaders();
		ResponseEntity<Void> response = serverRunning.getForResponse("/sparklr2/photos?format=json", headers);
		assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
		String authenticate = response.getHeaders().getFirst("WWW-Authenticate");
		assertTrue("Wrong header: " + authenticate, authenticate.contains("error=\"unauthorized\""));
	}

	@Test
	public void testInvalidTokenErrorMessage() throws Exception {
		HttpHeaders headers = new HttpHeaders();
		headers.set("Authorization", "Bearer FOO");
		ResponseEntity<Void> response = serverRunning.getForResponse("/sparklr2/photos?format=json", headers);
		assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
		String authenticate = response.getHeaders().getFirst("WWW-Authenticate");
		assertTrue("Wrong header: " + authenticate, authenticate.contains("error=\"invalid_token\""));
	}

	@Test
	@OAuth2ContextConfiguration(ResourceOwner.class)
	public void testTokenObtainedWithHeaderAuthentication() throws Exception {
		assertEquals(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/photos?format=json"));
		int expiry = context.getAccessToken().getExpiresIn();
		assertTrue("Expiry not overridden in config: " + expiry, expiry < 1000);
		assertEquals(new MediaType("application", "json", Charset.forName("UTF-8")), tokenEndpointResponse.getHeaders()
				.getContentType());
	}

	@Test
	@OAuth2ContextConfiguration(ResourceOwnerQuery.class)
	public void testTokenObtainedWithQueryAuthentication() throws Exception {
		assertEquals(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/photos?format=json"));
	}

	@Test
	@OAuth2ContextConfiguration(resource = ResourceOwnerNoSecretProvided.class, initialize = false)
	public void testTokenNotGrantedIfSecretNotProvided() throws Exception {
		try {
			context.getAccessToken();
		}
		catch (HttpClientErrorException e) {
			assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
			List<String> values = tokenEndpointResponse.getHeaders().get("WWW-Authenticate");
			assertEquals(1, values.size());
			assertTrue(values.get(0).contains("Basic realm=\"sparklr2/client\""));
		}
	}

	@Test
	@OAuth2ContextConfiguration(ResourceOwnerSecretProvidedInForm.class)
	public void testSecretProvidedInForm() throws Exception {
		assertEquals(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/photos?format=json"));
	}

	@Test
	@OAuth2ContextConfiguration(ResourceOwnerSecretProvided.class)
	public void testSecretProvidedInHeader() throws Exception {
		assertEquals(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/photos?format=json"));
	}

	@Test
	@OAuth2ContextConfiguration(resource = InvalidGrantType.class, initialize = false)
	public void testInvalidGrantType() throws Exception {
		
		// The error comes back as additional information because OAuth2AccessToken is so extensible!
		try {
			context.getAccessToken();
		}
		catch (Exception e) {
			// assertEquals("invalid_client", e.getOAuth2ErrorCode());
		}

		assertEquals(HttpStatus.UNAUTHORIZED, tokenEndpointResponse.getStatusCode());

		List<String> newCookies = tokenEndpointResponse.getHeaders().get("Set-Cookie");
		if (newCookies != null && !newCookies.isEmpty()) {
			fail("No cookies should be set. Found: " + newCookies.get(0) + ".");
		}

	}

	@Test
	public void testUserMessageIsProtectedResource() throws Exception {
		assertEquals(HttpStatus.UNAUTHORIZED, serverRunning.getStatusCode("/sparklr2/photos/user/message"));
	}

	@Test
	@OAuth2ContextConfiguration(ResourceOwnerWithTrustedClient.class)
	public void testClientRoleBasedSecurity() throws Exception {
		assertEquals(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/photos/user/message"));
	}

	/**
	 * tests a happy-day flow of the native application provider.
	 */
	@Test
	@OAuth2ContextConfiguration(ResourceOwnerWithTrustedClient.class)
	public void testUnsupportedMediaType() throws Exception {
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_XML));
		// Oddly enough this passes - the payload is a String so the message converter thinks it can handle it
		// the caller will get a surprise when he finds that the response is not actually XML, but that's a different
		// story.
		assertEquals(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/photos/user/message", headers));
	}

	/**
	 * tests that we get the correct error response if the media type is unacceptable.
	 */
	@Test
	public void testUnsupportedMediaTypeWithInvalidToken() throws Exception {
		HttpHeaders headers = new HttpHeaders();
		headers.set("Authorization", String.format("%s %s", OAuth2AccessToken.BEARER_TYPE, "FOO"));
		headers.setAccept(Arrays.asList(MediaType.valueOf("text/foo")));
		assertEquals(HttpStatus.NOT_ACCEPTABLE, serverRunning.getStatusCode("/sparklr2/photos/user/message", headers));
	}

	/**
	 * tests that we get the correct error response if the media type is unacceptable.
	 */
	@Test
	public void testMissingGrantType() throws Exception {
		HttpHeaders headers = new HttpHeaders();
		headers.set("Authorization", String.format("Basic %s", new String(Base64.encode("my-trusted-client:".getBytes()))));
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		ResponseEntity<String> response = serverRunning.postForString("/sparklr2/oauth/token", headers, new LinkedMultiValueMap<String, String>());
		assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
		assertTrue(response.getBody().contains("invalid_request"));
	}

	static class ResourceOwner extends ResourceOwnerPasswordResourceDetails {
		public ResourceOwner(Object target) {
			setClientId("my-trusted-client");
			setScope(Arrays.asList("read"));
			setId(getClientId());
			setUsername("marissa");
			setPassword("koala");
			TestResourceOwnerPasswordProvider test = (TestResourceOwnerPasswordProvider) target;
			setAccessTokenUri(test.serverRunning.getUrl("/sparklr2/oauth/token"));
		}
	}

	static class ResourceOwnerQuery extends ResourceOwner {
		public ResourceOwnerQuery(Object target) {
			super(target);
			setAuthenticationScheme(AuthenticationScheme.query);
		}
	}

	static class ResourceOwnerNoSecretProvided extends ResourceOwner {
		public ResourceOwnerNoSecretProvided(Object target) {
			super(target);
			setClientId("my-trusted-client-with-secret");
		}
	}

	static class ResourceOwnerSecretProvided extends ResourceOwner {
		public ResourceOwnerSecretProvided(Object target) {
			super(target);
			setClientId("my-trusted-client-with-secret");
			setClientSecret("somesecret");
		}
	}

	static class ResourceOwnerSecretProvidedInForm extends ResourceOwnerSecretProvided {
		public ResourceOwnerSecretProvidedInForm(Object target) {
			super(target);
			setAuthenticationScheme(AuthenticationScheme.form);
		}
	}

	static class InvalidGrantType extends ResourceOwner {
		public InvalidGrantType(Object target) {
			super(target);
			setClientId("my-untrusted-client-with-registered-redirect");
		}
	}

	static class ResourceOwnerWithTrustedClient extends ResourceOwner {
		public ResourceOwnerWithTrustedClient(Object target) {
			super(target);
			setClientId("my-trusted-client");
			setScope(Arrays.asList("trust"));
		}
	}

}
