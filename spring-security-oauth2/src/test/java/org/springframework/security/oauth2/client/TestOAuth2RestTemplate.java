package org.springframework.security.oauth2.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.client.http.AccessTokenRequiredException;
import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.ResponseExtractor;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class TestOAuth2RestTemplate {

	private BaseOAuth2ProtectedResourceDetails resource;

	private OAuth2RestTemplate restTemplate;

	private AccessTokenProvider accessTokenProvider = Mockito.mock(AccessTokenProvider.class);

	private ClientHttpRequest request;

	private HttpHeaders headers;

	@Before
	public void open() throws Exception {
		resource = new BaseOAuth2ProtectedResourceDetails();
		// Facebook and older specs:
		resource.setTokenName("bearer_token");
		restTemplate = new OAuth2RestTemplate(resource);
		restTemplate.setAccessTokenProvider(accessTokenProvider);
		request = Mockito.mock(ClientHttpRequest.class);
		headers = new HttpHeaders();
		Mockito.when(request.getHeaders()).thenReturn(headers);
		ClientHttpResponse response = Mockito.mock(ClientHttpResponse.class);
		HttpStatus statusCode = HttpStatus.OK;
		Mockito.when(response.getStatusCode()).thenReturn(statusCode);
		Mockito.when(request.execute()).thenReturn(response);
	}

	/**
	 * tests appendQueryParameter
	 */
	@Test
	public void testAppendQueryParameter() throws Exception {
		OAuth2AccessToken token = new DefaultOAuth2AccessToken("12345");
		URI appended = restTemplate.appendQueryParameter(URI.create("https://graph.facebook.com/search?type=checkin"),
				token);
		assertEquals("https://graph.facebook.com/search?type=checkin&bearer_token=12345", appended.toString());
	}

	/**
	 * tests appendQueryParameter
	 */
	@Test
	public void testAppendQueryParameterWithNoExistingParameters() throws Exception {
		OAuth2AccessToken token = new DefaultOAuth2AccessToken("12345");
		URI appended = restTemplate.appendQueryParameter(URI.create("https://graph.facebook.com/search"), token);
		assertEquals("https://graph.facebook.com/search?bearer_token=12345", appended.toString());
	}

	/**
	 * tests encoding of access token value
	 */
	@Test
	public void testDoubleEncodingOfParameterValue() throws Exception {
		OAuth2AccessToken token = new DefaultOAuth2AccessToken("1/qIxxx");
		URI appended = restTemplate.appendQueryParameter(URI.create("https://graph.facebook.com/search"), token);
		assertEquals("https://graph.facebook.com/search?bearer_token=1%2FqIxxx", appended.toString());
	}

	/**
	 * tests URI with fragment value
	 */
	@Test
	public void testFragmentUri() throws Exception {
		OAuth2AccessToken token = new DefaultOAuth2AccessToken("1234");
		URI appended = restTemplate.appendQueryParameter(URI.create("https://graph.facebook.com/search#foo"), token);
		assertEquals("https://graph.facebook.com/search?bearer_token=1234#foo", appended.toString());
	}

	/**
	 * tests encoding of access token value passed in protected requests ref: SECOAUTH-90
	 */
	@Test
	public void testDoubleEncodingOfAccessTokenValue() throws Exception {
		// try with fictitious token value with many characters to encode
		OAuth2AccessToken token = new DefaultOAuth2AccessToken("1 qI+x:y=z");
		// System.err.println(UriUtils.encodeQueryParam(token.getValue(), "UTF-8"));
		URI appended = restTemplate.appendQueryParameter(URI.create("https://graph.facebook.com/search"), token);
		assertEquals("https://graph.facebook.com/search?bearer_token=1+qI%2Bx%3Ay%3Dz", appended.toString());
	}

	@Test(expected=AccessTokenRequiredException.class)
	public void testNoRetryAccessDeniedExceptionForNoExistingToken() throws Exception {
		final AtomicBoolean failed = new AtomicBoolean(false);
		restTemplate.setAccessTokenProvider(new StubAccessTokenProvider());
		restTemplate.setRequestFactory(new ClientHttpRequestFactory() {
			public ClientHttpRequest createRequest(URI uri, HttpMethod httpMethod) throws IOException {
				if (!failed.get()) {
					failed.set(true);
					throw new AccessTokenRequiredException(resource);
				}
				return request;
			}
		});
		restTemplate.doExecute(new URI("http://foo"), HttpMethod.GET, new NullRequestCallback(), new SimpleResponseExtractor());
	}

	@Test
	public void testRetryAccessDeniedException() throws Exception {
		final AtomicBoolean failed = new AtomicBoolean(false);
		restTemplate.getOAuth2ClientContext().setAccessToken(new DefaultOAuth2AccessToken("TEST"));
		restTemplate.setAccessTokenProvider(new StubAccessTokenProvider());
		restTemplate.setRequestFactory(new ClientHttpRequestFactory() {
			public ClientHttpRequest createRequest(URI uri, HttpMethod httpMethod) throws IOException {
				if (!failed.get()) {
					failed.set(true);
					throw new AccessTokenRequiredException(resource);
				}
				return request;
			}
		});
		Boolean result = restTemplate.doExecute(new URI("http://foo"), HttpMethod.GET, new NullRequestCallback(), new SimpleResponseExtractor());
		assertTrue(result);
	}

	private final class SimpleResponseExtractor implements ResponseExtractor<Boolean> {
		public Boolean extractData(ClientHttpResponse response) throws IOException {
			return true;
		}
	}

	private static class NullRequestCallback implements RequestCallback {
		public void doWithRequest(ClientHttpRequest request) throws IOException {
		}
	}

	private static class StubAccessTokenProvider implements AccessTokenProvider {
		public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails details, AccessTokenRequest parameters)
				throws UserRedirectRequiredException, AccessDeniedException {
			return new DefaultOAuth2AccessToken("FOO");
		}

		public boolean supportsRefresh(OAuth2ProtectedResourceDetails resource) {
			return false;
		}

		public OAuth2AccessToken refreshAccessToken(OAuth2ProtectedResourceDetails resource,
				OAuth2RefreshToken refreshToken, AccessTokenRequest request) throws UserRedirectRequiredException {
			return null;
		}

		public boolean supportsResource(OAuth2ProtectedResourceDetails resource) {
			return true;
		}
	}

}
