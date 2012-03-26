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
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.Map;
import java.util.StringTokenizer;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.ServerRunning.UriBuilder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * @author Dave Syer
 * @author Luke Taylor
 */
public class TestAuthorizationCodeProvider {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	@Test
	public void testAuthorizationRequestRedirectsToLogin() throws Exception {

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.TEXT_HTML));

		String location = getAuthorizeUrl("my-less-trusted-client", "http://anywhere", "read");
		ResponseEntity<Void> result = serverRunning.getForResponse(location, headers);
		assertEquals(HttpStatus.FOUND, result.getStatusCode());
		location = result.getHeaders().getLocation().toString();

		if (result.getHeaders().containsKey("Set-Cookie")) {
			String cookie = result.getHeaders().getFirst("Set-Cookie");
			headers.set("Cookie", cookie);
		}

		ResponseEntity<String> response = serverRunning.getForString(location, headers);
		// should be directed to the login screen...
		assertTrue(response.getBody().contains("/login.do"));
		assertTrue(response.getBody().contains("j_username"));
		assertTrue(response.getBody().contains("j_password"));

	}

	@Test
	public void testSuccessfulAuthorizationCodeFlow() throws Exception {

		String code = getAuthorizationCode("my-less-trusted-client", "http://anywhere", "read");
		// Get the token using the authorization code (no session required because it's a back channel)
		OAuth2AccessToken accessToken = getAccessToken("my-less-trusted-client", "http://anywhere", code);

		// first make sure the resource is actually protected.
		assertNotSame(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/photos?format=json"));

		// now make sure an authorized request is valid.
		HttpHeaders headers = new HttpHeaders();
		headers.set("Authorization", String.format("%s %s", OAuth2AccessToken.BEARER_TYPE, accessToken.getValue()));
		assertEquals(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/photos?format=json", headers));

	}

	@Test
	public void testWrongRedirectUri() throws Exception {
		String code = getAuthorizationCode("my-less-trusted-client", "http://anywhere", "read");
		// Try and get a token with the wrong redirect uri
		confirmTokenRequestError("my-less-trusted-client", "http://nowhere", code, "read", HttpStatus.BAD_REQUEST,
				"redirect_uri_mismatch");
	}

	private void confirmTokenRequestError(String string, String string2, String code, String string3,
			HttpStatus badRequest, String string4) {
		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = requestToken("my-less-trusted-client", "http://nowhere", code, "read");
		assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
		assertTrue(response.getBody().containsKey("error"));
		assertEquals("redirect_uri_mismatch", response.getBody().get("error"));
	}

	@Test
	public void testUserDeniesConfirmation() throws Exception {

		String cookie = loginAndGetConfirmationPage("my-less-trusted-client", "http://anywhere", "read");

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.TEXT_HTML));
		headers.set("Cookie", cookie);

		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("user_oauth_approval", "false");
		ResponseEntity<Void> result = serverRunning.postForStatus("/sparklr2/oauth/authorize", headers, formData);
		assertEquals(HttpStatus.FOUND, result.getStatusCode());

		String location = result.getHeaders().getFirst("Location");
		assertTrue(location.startsWith("http://anywhere"));
		assertTrue(location.substring(location.indexOf('?')).contains("error=access_denied"));
		assertTrue(location.contains("state=mystateid"));

	}

	@Test
	public void testNoClientIdProvided() throws Exception {
		ResponseEntity<Void> response = attemptToGetConfirmationPage(null, "http://anywhere");
		// With no client id you get an InvalidClientException on the server which is redirected to /login
		// TODO: make a better fist of alerting the user or server admin that there was a problem
		assertEquals(HttpStatus.FOUND, response.getStatusCode());
		assertTrue(response.getHeaders().getLocation().toString().contains("login.jsp"));
	}

	@Test
	public void testNoRedirect() throws Exception {
		ResponseEntity<Void> response = attemptToGetConfirmationPage("my-less-trusted-client", null);
		// With no redirect uri you get an UnapprovedClientAuthenticationException on the server which is redirected to
		// /login
		// TODO: make a better fist of alerting the user or server admin that there was a problem
		assertEquals(HttpStatus.FOUND, response.getStatusCode());
		assertTrue(response.getHeaders().getLocation().toString().contains("login.jsp"));
	}

	@Test
	public void testSuccessfulFlowWithRegisteredRedirect() throws Exception {

		String code = getAuthorizationCode("my-client-with-registered-redirect", null, "read");
		// Get the token using the authorization code (no session required because it's a back channel)
		OAuth2AccessToken accessToken = getAccessToken("my-client-with-registered-redirect",
				"http://anywhere?key=value", code);

		// first make sure the resource is actually protected.
		assertNotSame(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/photos?format=json"));

		// now make sure an authorized request is valid.
		HttpHeaders headers = new HttpHeaders();
		headers.set("Authorization", String.format("%s %s", OAuth2AccessToken.BEARER_TYPE, accessToken.getValue()));
		assertEquals(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/photos?format=json", headers));

	}

	@Test
	public void testInvalidScopeInTokenRequest() throws Exception {
		// Need to use the client with a redirect because "my-less-trusted-client" has no registered scopes
		String code = getAuthorizationCode("my-client-with-registered-redirect", "http://anywhere?key=value",
				"bogus");
		confirmTokenRequestError("my-client-with-registered-redirect", "http://anywhere.com?key=value", code, "bogus",
				HttpStatus.FORBIDDEN, "invalid_scope");
	}

	@Test
	public void testInvalidScopeInResourceRequest() throws Exception {

		// Need to use the client with a redirect because "my-less-trusted-client" has no registered scopes
		String code = getAuthorizationCode("my-client-with-registered-redirect", "http://anywhere?key=value", "trust");
		OAuth2AccessToken accessToken = getAccessToken("my-client-with-registered-redirect", "http://anywhere?key=value",
				code, "trust", HttpStatus.OK);
		assertNotNull(accessToken);

		// now make sure an unauthorized request fails the right way.
		HttpHeaders headers = new HttpHeaders();
		headers.set("Authorization", String.format("%s %s", OAuth2AccessToken.BEARER_TYPE, accessToken.getValue()));
		ResponseEntity<String> response = serverRunning.getForString("/sparklr2/photos?format=json", headers);
		assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());

		String authenticate = response.getHeaders().getFirst("WWW-Authenticate");
		assertNotNull(authenticate);
		assertTrue(authenticate.startsWith("Bearer"));
		assertTrue(authenticate.contains("scope=\""));

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
		// Resource Server doesn't know what scopes are required until teh token can be validated
		assertFalse(authenticate.contains("scope=\""));

	}

	@Test
	public void testRegisteredRedirectWithWrongRequestedRedirect() throws Exception {
		String cookie = loginAndGrabCookie();

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.TEXT_HTML));
		headers.set("Cookie", cookie);

		ResponseEntity<String> response = serverRunning.getForString(
				getAuthorizeUrl("my-client-with-registered-redirect", "http://nowhere", "read"), headers);
		assertEquals(HttpStatus.FOUND, response.getStatusCode());
		String location = response.getHeaders().getLocation().toString();
		// This one should redirect to the login page and not the bogus redirect_uri in the authorization request
		assertTrue(location.matches(serverRunning.getUrl("/sparklr2/login") + ".*"));
	}

	@Test
	public void testRegisteredRedirectWithNoRequestedRedirectAndWrongOneInTokenEndpoint() throws Exception {
		String code = getAuthorizationCode("my-client-with-registered-redirect", null, "read");
		// Get the token using the authorization code (no session required because it's a back channel)
		confirmTokenRequestError("my-client-with-registered-redirect", "http://nowhere.com", code, "read",
				HttpStatus.BAD_REQUEST, "redirect_uri_mismatch");
	}

	private String getAuthorizationCode(String clientId, String redirectUri, String scope) {
		String cookie = loginAndGetConfirmationPage(clientId, redirectUri, scope);
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.TEXT_HTML));
		headers.set("Cookie", cookie);
		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("user_oauth_approval", "true");
		ResponseEntity<Void> result = serverRunning.postForStatus("/sparklr2/oauth/authorize", headers, formData);
		assertEquals(HttpStatus.FOUND, result.getStatusCode());
		// Get the authorization code using the same session
		return getAuthorizationCode(result);
	}

	private ResponseEntity<Void> attemptToGetConfirmationPage(String clientId, String redirectUri) {

		String cookie = loginAndGrabCookie();

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.TEXT_HTML));
		headers.set("Cookie", cookie);

		return serverRunning.getForResponse(getAuthorizeUrl(clientId, redirectUri, "read"), headers);

	}

	private String loginAndGetConfirmationPage(String clientId, String redirectUri, String scope) {

		String cookie = loginAndGrabCookie();

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.TEXT_HTML));
		headers.set("Cookie", cookie);

		UriBuilder uri = serverRunning.buildUri("/sparklr2/oauth/authorize").queryParam("response_type", "code")
				.queryParam("state", "mystateid").queryParam("scope", scope);
		if (clientId != null) {
			uri.queryParam("client_id", clientId);
		}
		if (redirectUri != null) {
			uri.queryParam("redirect_uri", redirectUri);
		}

		ResponseEntity<String> response = serverRunning.getForString(uri.pattern(), headers, uri.params());
		// The confirm access page should be returned
		assertTrue(response.getBody().contains("Please Confirm"));

		return cookie;

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

	private OAuth2AccessToken getAccessToken(String clientId, String redirectUri, String cookie) {
		return getAccessToken(clientId, redirectUri, cookie, "read", HttpStatus.OK);
	}

	private OAuth2AccessToken getAccessToken(String clientId, String redirectUri, String cookie, String scope,
			HttpStatus expectedStatus) {

		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> map = requestToken(clientId, redirectUri, cookie, scope);

		assertEquals(expectedStatus, map.getStatusCode());

		if (HttpStatus.OK == map.getStatusCode()) {
			@SuppressWarnings("unchecked")
			OAuth2AccessToken accessToken = OAuth2AccessToken.valueOf(map.getBody());
			return accessToken;
		}

		return null;

	}

	@SuppressWarnings("rawtypes")
	private ResponseEntity<Map> requestToken(String clientId, String redirectUri, String cookie, String scope) {
		MultiValueMap<String, String> formData = getTokenFormData(clientId, redirectUri, cookie, scope);

		ResponseEntity<Map> map = serverRunning.postForMap("/sparklr2/oauth/token", formData);
		HttpHeaders responseHeaders = map.getHeaders();
		assertTrue("Missing no-store: " + responseHeaders, responseHeaders.get("Cache-Control").contains("no-store"));
		return map;
	}

	private MultiValueMap<String, String> getTokenFormData(String clientId, String redirectUri, String code,
			String scope) {
		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "authorization_code");
		formData.add("client_id", clientId);
		formData.add("scope", scope);
		formData.add("redirect_uri", redirectUri);
		formData.add("state", "mystateid");
		if (code != null) {
			formData.add("code", code);
		}
		return formData;
	}

	private String getAuthorizationCode(HttpEntity<Void> result) {

		String location = result.getHeaders().getLocation().toString();
		assertTrue(location.matches("http://.*code=.+"));

		String code = null;
		String state = null;
		for (StringTokenizer queryTokens = new StringTokenizer(result.getHeaders().getLocation().getQuery(), "&="); queryTokens
				.hasMoreTokens();) {
			String token = queryTokens.nextToken();
			if ("code".equals(token)) {
				if (code != null) {
					fail("shouldn't have returned more than one code.");
				}

				code = queryTokens.nextToken();
			}
			else if ("state".equals(token)) {
				state = queryTokens.nextToken();
			}
		}

		assertEquals("mystateid", state);
		assertNotNull(code);
		return code;

	}

	private String loginAndGrabCookie() {

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.TEXT_HTML));

		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("j_username", "marissa");
		formData.add("j_password", "koala");

		// Should be redirected to the original URL, but now authenticated
		ResponseEntity<Void> result = serverRunning.postForStatus("/sparklr2/login.do", headers, formData);
		assertEquals(HttpStatus.FOUND, result.getStatusCode());

		assertTrue(result.getHeaders().containsKey("Set-Cookie"));

		return result.getHeaders().getFirst("Set-Cookie");

	}

}
