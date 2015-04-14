package sparklr.common;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.ResponseExtractor;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
public abstract class AbstractResourceOwnerPasswordProviderTests extends
		AbstractIntegrationTests {

	protected ClientHttpResponse tokenEndpointResponse;

	@Override
	protected ResourceOwnerPasswordAccessTokenProvider createAccessTokenProvider() {
		ResourceOwnerPasswordAccessTokenProvider accessTokenProvider = new ResourceOwnerPasswordAccessTokenProvider() {

			@Override
			protected ResponseErrorHandler getResponseErrorHandler() {
				final ResponseErrorHandler errorHandler = super.getResponseErrorHandler();
				return new DefaultResponseErrorHandler() {
					public void handleError(ClientHttpResponse response)
							throws IOException {
						response.getHeaders();
						response.getStatusCode();
						tokenEndpointResponse = response;
						errorHandler.handleError(response);
					}
				};
			}

			@Override
			protected ResponseExtractor<OAuth2AccessToken> getResponseExtractor() {
				final ResponseExtractor<OAuth2AccessToken> extractor = super
						.getResponseExtractor();
				return new ResponseExtractor<OAuth2AccessToken>() {

					public OAuth2AccessToken extractData(ClientHttpResponse response)
							throws IOException {
						response.getHeaders();
						response.getStatusCode();
						tokenEndpointResponse = response;
						return extractor.extractData(response);
					}

				};
			}
		};
		return accessTokenProvider;
	}

	@Test
	public void testUnauthenticated() throws Exception {
		// first make sure the resource is actually protected.
		assertEquals(HttpStatus.UNAUTHORIZED, http.getStatusCode("/admin/beans"));
	}

	@Test
	public void testUnauthenticatedErrorMessage() throws Exception {
		HttpHeaders headers = new HttpHeaders();
		ResponseEntity<Void> response = http.getForResponse("/admin/beans", headers);
		assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
		String authenticate = response.getHeaders().getFirst("WWW-Authenticate");
		assertTrue("Wrong header: " + authenticate,
				authenticate.contains("error=\"unauthorized\""));
	}

	@Test
	public void testInvalidTokenErrorMessage() throws Exception {
		HttpHeaders headers = new HttpHeaders();
		headers.set("Authorization", "Bearer FOO");
		ResponseEntity<Void> response = http.getForResponse("/admin/beans", headers);
		assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
		String authenticate = response.getHeaders().getFirst("WWW-Authenticate");
		assertTrue("Wrong header: " + authenticate,
				authenticate.contains("error=\"invalid_token\""));
	}

	@Test
	@OAuth2ContextConfiguration(ResourceOwner.class)
	public void testTokenObtainedWithHeaderAuthentication() throws Exception {
		assertEquals(HttpStatus.OK, http.getStatusCode("/admin/beans"));
		int expiry = context.getAccessToken().getExpiresIn();
		assertTrue("Expiry not overridden in config: " + expiry, expiry < 1000);
		assertEquals(new MediaType("application", "json", Charset.forName("UTF-8")),
				tokenEndpointResponse.getHeaders().getContentType());
	}

	@Test
	@OAuth2ContextConfiguration(ResourceOwnerQuery.class)
	public void testTokenObtainedWithQueryAuthentication() throws Exception {
		assertEquals(HttpStatus.OK, http.getStatusCode("/admin/beans"));
	}

	@Test
	@OAuth2ContextConfiguration(resource = ResourceOwnerNoSecretProvided.class, initialize = false)
	public void testTokenNotGrantedIfSecretNotProvided() throws Exception {
		try {
			context.getAccessToken();
		}
		catch (HttpClientErrorException e) {
			assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
			List<String> values = tokenEndpointResponse.getHeaders().get(
					"WWW-Authenticate");
			assertEquals(1, values.size());
			String header = values.get(0);
			assertTrue("Wrong header " + header,
					header.contains("realm=\"oauth2/client\""));
		}
	}

	@Test
	@OAuth2ContextConfiguration(ResourceOwnerSecretProvidedInForm.class)
	public void testSecretProvidedInForm() throws Exception {
		assertEquals(HttpStatus.OK, http.getStatusCode("/admin/beans"));
	}

	@Test
	@OAuth2ContextConfiguration(ResourceOwnerSecretProvided.class)
	public void testSecretProvidedInHeader() throws Exception {
		assertEquals(HttpStatus.OK, http.getStatusCode("/admin/beans"));
	}

	@Test
	@OAuth2ContextConfiguration(resource = NoSuchClient.class, initialize = false)
	public void testNoSuchClient() throws Exception {

		// The error comes back as additional information because OAuth2AccessToken is so
		// extensible!
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
	@OAuth2ContextConfiguration(value=ResourceOwner.class, initialize=false)
	public void testTokenEndpointWrongPassword() throws Exception {
		ResourceOwnerPasswordResourceDetails resource = (ResourceOwnerPasswordResourceDetails) context
				.getResource();
		resource.setPassword("bogus");
		try {			
			new OAuth2RestTemplate(resource).getAccessToken();
		} catch (OAuth2AccessDeniedException e) {
			String summary = ((OAuth2Exception)e.getCause()).getSummary();
			assertTrue("Wrong summary: " + summary, summary.contains("Bad credentials"));
		}
	}

	@Test
	public void testTokenEndpointUnauthenticated() throws Exception {
		ResponseEntity<String> result = http.getRestTemplate().exchange(
				http.getUrl("/oauth/token"), HttpMethod.GET,
				new HttpEntity<Void>((Void) null), String.class);
		// first make sure the resource is actually protected.
		assertEquals(HttpStatus.UNAUTHORIZED, result.getStatusCode());
		assertTrue("Wrong body: " + result.getBody(),
				result.getBody().toLowerCase().contains("unauthorized"));
	}

	@Test
	@OAuth2ContextConfiguration(resource = InvalidGrantType.class, initialize = false)
	public void testInvalidGrantType() throws Exception {

		// The error comes back as additional information because OAuth2AccessToken is so
		// extensible!
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

	/**
	 * tests that we get the correct error response if the media type is unacceptable.
	 */
	@Test
	public void testMissingGrantType() throws Exception {
		HttpHeaders headers = new HttpHeaders();
		headers.set(
				"Authorization",
				String.format("Basic %s",
						new String(Base64.encode("my-trusted-client:".getBytes()))));
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		ResponseEntity<String> response = http.postForString(tokenPath(), headers,
				new LinkedMultiValueMap<String, String>());
		assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
		assertTrue(response.getBody().contains("invalid_request"));
	}

	protected static class ResourceOwner extends ResourceOwnerPasswordResourceDetails {
		public ResourceOwner(Object target) {
			setClientId("my-trusted-client");
			setScope(Arrays.asList("read"));
			setId(getClientId());
			setUsername("user");
			setPassword("password");
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
			setClientId("my-client-with-secret");
		}
	}

	static class ResourceOwnerSecretProvided extends ResourceOwner {
		public ResourceOwnerSecretProvided(Object target) {
			super(target);
			setClientId("my-client-with-secret");
			setClientSecret("secret");
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
			setClientId("my-client-with-registered-redirect");
		}
	}

	static class NoSuchClient extends ResourceOwner {
		public NoSuchClient(Object target) {
			super(target);
			setClientId("no-such-client");
		}
	}

}
