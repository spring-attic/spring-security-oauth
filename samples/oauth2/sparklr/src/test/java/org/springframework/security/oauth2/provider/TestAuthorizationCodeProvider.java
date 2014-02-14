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
package org.springframework.security.oauth2.provider;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.client.resource.UserApprovalRequiredException;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.test.BeforeOAuth2Context;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.ServerRunning.UriBuilder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.ResponseExtractor;

/**
 * @author Dave Syer
 * @author Luke Taylor
 */
public class TestAuthorizationCodeProvider {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	@Rule
	public OAuth2ContextSetup context = OAuth2ContextSetup.standard(serverRunning);

	private AuthorizationCodeAccessTokenProvider accessTokenProvider;

	private String cookie;

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
						response.getHeaders();
						response.getStatusCode();
						tokenEndpointResponse = response;
						return extractor.extractData(response);
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
		context.setAccessTokenProvider(accessTokenProvider);
	}

	@BeforeOAuth2Context
	public void loginAndExtractCookie() {
		this.cookie = loginAndGrabCookie();
	}

	@Test
	public void testResourceIsProtected() throws Exception {
		// first make sure the resource is actually protected.
		assertEquals(HttpStatus.UNAUTHORIZED, serverRunning.getStatusCode("/sparklr2/photos?format=json"));
	}

	@Test
	@OAuth2ContextConfiguration(resource = MyLessTrustedClient.class, initialize = false)
	public void testUnauthenticatedAuthorizationRequestRedirectsToLogin() throws Exception {

		AccessTokenRequest request = context.getAccessTokenRequest();
		request.setCurrentUri("http://anywhere");
		request.add(OAuth2Utils.USER_OAUTH_APPROVAL, "true");

		String location = null;

		try {
			String code = accessTokenProvider.obtainAuthorizationCode(context.getResource(), request);
			assertNotNull(code);
			fail("Expected UserRedirectRequiredException");
		}
		catch (UserRedirectRequiredException e) {
			location = e.getRedirectUri();
		}

		assertNotNull(location);
		assertEquals(serverRunning.getUrl("/sparklr2/login.jsp"), location);

	}

	@Test
	@OAuth2ContextConfiguration(resource = MyLessTrustedClient.class, initialize = false)
	public void testSuccessfulAuthorizationCodeFlow() throws Exception {

		// Once the request is ready and approved, we can continue with the access token
		approveAccessTokenGrant("http://anywhere", true);

		// Finally everything is in place for the grant to happen...
		assertNotNull(context.getAccessToken());

		AccessTokenRequest request = context.getAccessTokenRequest();
		assertNotNull(request.getAuthorizationCode());
		assertEquals(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/photos?format=json"));

	}

	@Test
	@OAuth2ContextConfiguration(resource = MyLessTrustedClient.class, initialize = false)
	public void testWrongRedirectUri() throws Exception {
		approveAccessTokenGrant("http://anywhere", true);
		AccessTokenRequest request = context.getAccessTokenRequest();
		// The redirect is stored in the preserved state...
		context.getOAuth2ClientContext().setPreservedState(request.getStateKey(), "http://nowhere");
		// Finally everything is in place for the grant to happen...
		try {
			assertNotNull(context.getAccessToken());
			fail("Expected RedirectMismatchException");
		}
		catch (RedirectMismatchException e) {
			// expected
		}
		assertEquals(HttpStatus.BAD_REQUEST, tokenEndpointResponse.getStatusCode());
	}

	@Test
	@OAuth2ContextConfiguration(resource = MyLessTrustedClient.class, initialize = false)
	public void testUserDeniesConfirmation() throws Exception {
		approveAccessTokenGrant("http://anywhere", false);
		String location = null;
		try {
			assertNotNull(context.getAccessToken());
			fail("Expected UserRedirectRequiredException");
		}
		catch (UserRedirectRequiredException e) {
			location = e.getRedirectUri();
		}
		assertTrue("Wrong location: " + location, location.contains("state="));
		assertTrue(location.startsWith("http://anywhere"));
		assertTrue(location.substring(location.indexOf('?')).contains("error=access_denied"));
		// It was a redirect that triggered our client redirect exception:
		assertEquals(HttpStatus.FOUND, tokenEndpointResponse.getStatusCode());
	}

	@Test
	public void testNoClientIdProvided() throws Exception {
		ResponseEntity<String> response = attemptToGetConfirmationPage(null, "http://anywhere");
		// With no client id you get an InvalidClientException on the server which is forwarded to /oauth/error
		assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
		String body = response.getBody();
		assertTrue("Wrong body: " + body, body.contains("<html"));
		assertTrue("Wrong body: " + body, body.contains("OAuth2 Error"));
	}

	@Test
	public void testNoRedirect() throws Exception {
		ResponseEntity<String> response = attemptToGetConfirmationPage("my-less-trusted-client", null);
		// With no redirect uri you get an UnapprovedClientAuthenticationException on the server which is redirected to
		// /oauth/error.
		assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
		String body = response.getBody();
		assertTrue("Wrong body: " + body, body.contains("<html"));
		assertTrue("Wrong body: " + body, body.contains("OAuth2 Error"));
	}

	@Test
	public void testIllegalAttemptToApproveWithoutUsingAuthorizationRequest() throws Exception {

		if (cookie == null) {
			cookie = loginAndGrabCookie();
		}

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.TEXT_HTML));
		headers.set("Cookie", cookie);

		String authorizeUrl = getAuthorizeUrl("my-less-trusted-client", "http://anywhere.com", "read");
		authorizeUrl = authorizeUrl + "&user_oauth_approval=true";
		ResponseEntity<Void> response = serverRunning.postForStatus(authorizeUrl, headers,
				new LinkedMultiValueMap<String, String>());
		assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
	}

	@Test
	@OAuth2ContextConfiguration(resource = MyClientWithRegisteredRedirect.class, initialize = false)
	public void testSuccessfulFlowWithRegisteredRedirect() throws Exception {

		// Once the request is ready and approved, we can continue with the access token
		approveAccessTokenGrant(null, true);

		// Finally everything is in place for the grant to happen...
		assertNotNull(context.getAccessToken());

		AccessTokenRequest request = context.getAccessTokenRequest();
		assertNotNull(request.getAuthorizationCode());
		assertEquals(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/photos?format=json"));

	}

	@Test
	public void testInvalidScopeInAuthorizationRequest() throws Exception {
		// Need to use the client with a redirect because "my-less-trusted-client" has no registered scopes
		String cookie = loginAndGrabCookie();

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.TEXT_HTML));
		headers.set("Cookie", cookie);

		String scope = "bogus";
		String redirectUri = "http://anywhere?key=value";
		String clientId = "my-client-with-registered-redirect";

		UriBuilder uri = serverRunning.buildUri("/sparklr2/oauth/authorize").queryParam("response_type", "code")
				.queryParam("state", "mystateid").queryParam("scope", scope);
		if (clientId != null) {
			uri.queryParam("client_id", clientId);
		}
		if (redirectUri != null) {
			uri.queryParam("redirect_uri", redirectUri);
		}
		ResponseEntity<String> response = serverRunning.getForString(uri.pattern(), headers, uri.params());
		assertEquals(HttpStatus.FOUND, response.getStatusCode());
		String location = response.getHeaders().getLocation().toString();
		assertTrue(location.startsWith("http://anywhere"));
		assertTrue(location.contains("error=invalid_scope"));
		assertFalse(location.contains("redirect_uri="));
	}

	@Test
	@OAuth2ContextConfiguration(resource = MyClientWithRegisteredRedirect.class, initialize = false)
	public void testInsufficientScopeInResourceRequest() throws Exception {
		AuthorizationCodeResourceDetails resource = (AuthorizationCodeResourceDetails) context.getResource();
		resource.setScope(Arrays.asList("trust"));
		approveAccessTokenGrant("http://anywhere?key=value", true);
		assertNotNull(context.getAccessToken());
		try {
			serverRunning.getForString("/sparklr2/photos?format=json");
			fail("Should have thrown exception");
		}
		catch (InsufficientScopeException ex) {
			// ignore / all good
		}
	}

	@Test
	public void testInvalidAccessToken() throws Exception {

		// now make sure an unauthorized request fails the right way.
		HttpHeaders headers = new HttpHeaders();
		headers.set("Authorization", String.format("%s %s", OAuth2AccessToken.BEARER_TYPE, "FOO"));
		ResponseEntity<String> response = serverRunning.getForString("/sparklr2/photos?format=json", headers);
		assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());

		String authenticate = response.getHeaders().getFirst("WWW-Authenticate");
		assertNotNull(authenticate);
		assertTrue(authenticate.startsWith("Bearer"));
		// Resource Server doesn't know what scopes are required until the token can be validated
		assertFalse(authenticate.contains("scope=\""));

	}

	@Test
	@OAuth2ContextConfiguration(resource = MyClientWithRegisteredRedirect.class, initialize = false)
	public void testRegisteredRedirectWithWrongRequestedRedirect() throws Exception {
		try {
			approveAccessTokenGrant("http://nowhere", true);
			fail("Expected RedirectMismatchException");
		}
		catch (RedirectMismatchException e) {
		}
		assertEquals(HttpStatus.BAD_REQUEST, tokenEndpointResponse.getStatusCode());
	}

	@Test
	@OAuth2ContextConfiguration(resource = MyClientWithRegisteredRedirect.class, initialize = false)
	public void testRegisteredRedirectWithWrongOneInTokenEndpoint() throws Exception {
		approveAccessTokenGrant("http://anywhere?key=value", true);
		// Setting the redirect uri directly in the request shoiuld override the saved value
		context.getAccessTokenRequest().set("redirect_uri", "http://nowhere.com");
		try {
			assertNotNull(context.getAccessToken());
			fail("Expected RedirectMismatchException");
		}
		catch (RedirectMismatchException e) {
		}
		assertEquals(HttpStatus.BAD_REQUEST, tokenEndpointResponse.getStatusCode());
	}

	private ResponseEntity<String> attemptToGetConfirmationPage(String clientId, String redirectUri) {

		if (cookie == null) {
			cookie = loginAndGrabCookie();
		}

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.TEXT_HTML));
		headers.set("Cookie", cookie);

		return serverRunning.getForString(getAuthorizeUrl(clientId, redirectUri, "read"), headers);

	}

	private String getAuthorizeUrl(String clientId, String redirectUri, String scope) {
		UriBuilder uri = serverRunning.buildUri("/sparklr2/oauth/authorize").queryParam("response_type", "code")
				.queryParam("state", "mystateid").queryParam("scope", scope);
		if (clientId != null) {
			uri.queryParam("client_id", clientId);
		}
		if (redirectUri != null) {
			uri.queryParam("redirect_uri", redirectUri);
		}
		return uri.build().toString();
	}

	private String loginAndGrabCookie() {

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
		HttpHeaders headers = new HttpHeaders();
		headers.set("Cookie", cookie);
		headers.setAccept(Arrays.asList(MediaType.TEXT_HTML));
		ResponseEntity<Void> result = serverRunning.postForStatus(location, headers , formData);
		assertEquals(HttpStatus.FOUND, result.getStatusCode());
		cookie = result.getHeaders().getFirst("Set-Cookie");

		assertNotNull("Expected cookie in " + result.getHeaders(), cookie);

		return cookie;

	}

	private void approveAccessTokenGrant(String currentUri, boolean approved) {

		AccessTokenRequest request = context.getAccessTokenRequest();
		AuthorizationCodeResourceDetails resource = (AuthorizationCodeResourceDetails) context.getResource();

		request.setCookie(cookie);
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

	static class MyLessTrustedClient extends AuthorizationCodeResourceDetails {
		public MyLessTrustedClient(Object target) {
			super();
			setClientId("my-less-trusted-client");
			setScope(Arrays.asList("read"));
			setId(getClientId());
			TestAuthorizationCodeProvider test = (TestAuthorizationCodeProvider) target;
			setAccessTokenUri(test.serverRunning.getUrl("/sparklr2/oauth/token"));
			setUserAuthorizationUri(test.serverRunning.getUrl("/sparklr2/oauth/authorize"));
		}
	}

	static class MyClientWithRegisteredRedirect extends MyLessTrustedClient {
		public MyClientWithRegisteredRedirect(Object target) {
			super(target);
			setClientId("my-client-with-registered-redirect");
			setPreEstablishedRedirectUri("http://anywhere?key=value");
		}
	}
}
