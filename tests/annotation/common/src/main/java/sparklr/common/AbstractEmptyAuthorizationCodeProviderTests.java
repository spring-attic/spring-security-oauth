/*
 * Copyright 2006-2011 the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package sparklr.common;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.UserApprovalRequiredException;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.test.BeforeOAuth2Context;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.util.StreamUtils;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.ResponseExtractor;

import sparklr.common.HttpTestUtils.UriBuilder;

/**
 * @author Dave Syer
 * @author Luke Taylor
 */
public abstract class AbstractEmptyAuthorizationCodeProviderTests extends AbstractIntegrationTests {

	private AuthorizationCodeAccessTokenProvider accessTokenProvider;

	private ClientHttpResponse tokenEndpointResponse;

	@BeforeOAuth2Context
	public void setupAccessTokenProvider() {
		accessTokenProvider = new AuthorizationCodeAccessTokenProvider() {

			private ResponseExtractor<OAuth2AccessToken> extractor = super.getResponseExtractor();

			private ResponseExtractor<ResponseEntity<Void>> authExtractor = super.getAuthorizationResponseExtractor();

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
						try {
							response.getHeaders();
							response.getStatusCode();
							tokenEndpointResponse = response;
							return extractor.extractData(response);
						}
						catch (ResourceAccessException e) {
							return null;
						}
					}

				};
			}

			@Override
			protected ResponseExtractor<ResponseEntity<Void>> getAuthorizationResponseExtractor() {
				return new ResponseExtractor<ResponseEntity<Void>>() {

					public ResponseEntity<Void> extractData(ClientHttpResponse response) throws IOException {
						response.getHeaders();
						response.getStatusCode();
						tokenEndpointResponse = response;
						return authExtractor.extractData(response);
					}
				};
			}
		};
		context.setAccessTokenProvider(getAccessTokenProvider());
	}

	protected ResponseEntity<String> attemptToGetConfirmationPage(String clientId, String redirectUri) {
		return attemptToGetConfirmationPage(clientId, redirectUri, "code");
	}

	protected ResponseEntity<String> attemptToGetConfirmationPage(String clientId, String redirectUri,
			String responseType) {
		HttpHeaders headers = getAuthenticatedHeaders();
		return http.getForString(getAuthorizeUrl(clientId, redirectUri, responseType, "read"), headers);
	}

	private String getAuthorizeUrl(String clientId, String redirectUri, String responseType, String scope) {
		UriBuilder uri = http.buildUri(authorizePath()).queryParam("state", "mystateid").queryParam("scope", scope);
		if (responseType != null) {
			uri.queryParam("response_type", responseType);
		}
		if (clientId != null) {
			uri.queryParam("client_id", clientId);
		}
		if (redirectUri != null) {
			uri.queryParam("redirect_uri", redirectUri);
		}
		return uri.build().toString();
	}
	
	protected HttpHeaders getAuthenticatedHeaders() {
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.TEXT_HTML));
		headers.set("Authorization", getBasicAuthentication());
		if (context.getRestTemplate() != null) {
			context.getAccessTokenRequest().setHeaders(headers);
		}
		return headers;
	}

	protected String getAuthorizeUrl(String clientId, String redirectUri, String scope) {
		UriBuilder uri = http.buildUri(authorizePath()).queryParam("response_type", "code")
				.queryParam("state", "mystateid").queryParam("scope", scope);
		if (clientId != null) {
			uri.queryParam("client_id", clientId);
		}
		if (redirectUri != null) {
			uri.queryParam("redirect_uri", redirectUri);
		}
		return uri.build().toString();
	}

	protected void approveAccessTokenGrant(String currentUri, boolean approved) {

		AccessTokenRequest request = context.getAccessTokenRequest();
		request.setHeaders(getAuthenticatedHeaders());
		AuthorizationCodeResourceDetails resource = (AuthorizationCodeResourceDetails) context.getResource();

		if (currentUri != null) {
			request.setCurrentUri(currentUri);
		}

		String location = null;

		try {
			// First try to obtain the access token...
			assertNotNull(context.getAccessToken());
			fail("Expected UserRedirectRequiredException");
		}
		catch (UserRedirectRequiredException e) {
			// Expected and necessary, so that the correct state is set up in the request...
			location = e.getRedirectUri();
		}

		assertTrue(location.startsWith(resource.getUserAuthorizationUri()));
		assertNull(request.getAuthorizationCode());

		verifyAuthorizationPage(context.getRestTemplate(), location);

		try {
			// Now try again and the token provider will redirect for user approval...
			assertNotNull(context.getAccessToken());
			fail("Expected UserRedirectRequiredException");
		}
		catch (UserApprovalRequiredException e) {
			// Expected and necessary, so that the user can approve the grant...
			location = e.getApprovalUri();
		}

		assertTrue(location.startsWith(resource.getUserAuthorizationUri()));
		assertNull(request.getAuthorizationCode());

		// The approval (will be processed on the next attempt to obtain an access token)...
		request.set(OAuth2Utils.USER_OAUTH_APPROVAL, "" + approved);

	}

	private void verifyAuthorizationPage(OAuth2RestTemplate restTemplate, String location) {
		final AtomicReference<String> confirmationPage = new AtomicReference<String>();
		AuthorizationCodeAccessTokenProvider provider = new AuthorizationCodeAccessTokenProvider() {
			@Override
			protected ResponseExtractor<ResponseEntity<Void>> getAuthorizationResponseExtractor() {
				return new ResponseExtractor<ResponseEntity<Void>>() {
					public ResponseEntity<Void> extractData(ClientHttpResponse response) throws IOException {
						confirmationPage.set(StreamUtils.copyToString(response.getBody(), Charset.forName("UTF-8")));
						return new ResponseEntity<Void>(response.getHeaders(), response.getStatusCode());
					}
				};
			}
		};
		try {
			provider.obtainAuthorizationCode(restTemplate.getResource(), restTemplate.getOAuth2ClientContext()
					.getAccessTokenRequest());
		}
		catch (UserApprovalRequiredException e) {
			// ignore
		}
		String page = confirmationPage.get();
		verifyAuthorizationPage(page);
	}

	protected void verifyAuthorizationPage(String page) {
	}

	protected AuthorizationCodeAccessTokenProvider getAccessTokenProvider() {
		return accessTokenProvider;
	}

	protected ClientHttpResponse getTokenEndpointResponse() {
		return tokenEndpointResponse;
	}

	protected static class MyTrustedClient extends AuthorizationCodeResourceDetails {
		public MyTrustedClient(Object target) {
			super();
			setClientId("my-trusted-client");
			setScope(Arrays.asList("read"));
			setId(getClientId());
		}
	}

	protected static class MyClientWithRegisteredRedirect extends MyTrustedClient {
		public MyClientWithRegisteredRedirect(Object target) {
			super(target);
			setClientId("my-client-with-registered-redirect");
			setPreEstablishedRedirectUri("http://anywhere?key=value");
		}
	}
}
