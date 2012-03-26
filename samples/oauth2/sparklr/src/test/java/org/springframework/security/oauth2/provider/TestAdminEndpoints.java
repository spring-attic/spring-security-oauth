package org.springframework.security.oauth2.provider;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Map;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * @author Dave Syer
 */
public class TestAdminEndpoints {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	@Test
	public void testListTokensByUser() throws Exception {

		OAuth2AccessToken token = getResourceOwnerPasswordAccessToken("read", "my-trusted-client");

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		headers.set("Authorization", "Bearer " + token.getValue());

		ResponseEntity<String> result = serverRunning.getForString("/sparklr2/oauth/users/marissa/tokens", headers);
		assertEquals(HttpStatus.OK, result.getStatusCode());
		// System.err.println(result.getBody());
		assertTrue(result.getBody().contains(token.getValue()));
	}

	@Test
	public void testRevokeTokenByUser() throws Exception {

		OAuth2AccessToken token = getResourceOwnerPasswordAccessToken("write", "my-trusted-client");

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		headers.set("Authorization", "Bearer " + token.getValue());

		HttpEntity<?> request = new HttpEntity<Void>(headers);
		assertEquals(
				HttpStatus.NO_CONTENT,
				serverRunning
						.getRestTemplate()
						.exchange(serverRunning.getUrl("/sparklr2/oauth/users/{user}/tokens/{token}"),
								HttpMethod.DELETE, request, Void.class, "marissa", token.getValue()).getStatusCode());

		ResponseEntity<String> result = serverRunning.getForString("/sparklr2/oauth/users/marissa/tokens", headers);
		assertEquals(HttpStatus.UNAUTHORIZED, result.getStatusCode());
		assertTrue(result.getBody().contains("invalid_token"));

	}

	@Test
	public void testClientListsTokensByUser() throws Exception {

		OAuth2AccessToken token = getClientCredentialsAccessToken("read", "my-client-with-registered-redirect");

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		headers.set("Authorization", "Bearer " + token.getValue());

		ResponseEntity<String> result = serverRunning.getForString("/sparklr2/oauth/users/marissa/tokens", headers);
		assertEquals(HttpStatus.OK, result.getStatusCode());
		assertTrue(result.getBody().startsWith("["));
		assertTrue(result.getBody().endsWith("]"));
		assertTrue(result.getBody().length() > 0);
	}

	@Test
	public void testCannotListTokensOfAnotherUser() throws Exception {

		OAuth2AccessToken token = getResourceOwnerPasswordAccessToken("read", "my-trusted-client");

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		headers.set("Authorization", "Bearer " + token.getValue());

		assertEquals(HttpStatus.FORBIDDEN, serverRunning.getStatusCode("/sparklr2/oauth/users/foo/tokens", headers));
	}

	@Test
	public void testListTokensByClient() throws Exception {

		OAuth2AccessToken token = getClientCredentialsAccessToken("read", "my-client-with-registered-redirect");

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		headers.set("Authorization", "Bearer " + token.getValue());

		ResponseEntity<String> result = serverRunning.getForString(
				"/sparklr2/oauth/clients/my-client-with-registered-redirect/tokens", headers);
		assertEquals(HttpStatus.OK, result.getStatusCode());
		assertTrue(result.getBody().contains(token.getValue()));
	}

	@Test
	public void testUserCannotListTokensOfClient() throws Exception {

		OAuth2AccessToken token = getResourceOwnerPasswordAccessToken("read", "my-trusted-client");

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		headers.set("Authorization", "Bearer " + token.getValue());

		assertEquals(HttpStatus.FORBIDDEN, serverRunning.getStatusCode(
				"/sparklr2/oauth/clients/my-client-with-registered-redirect/tokens", headers));
	}

	private OAuth2AccessToken getClientCredentialsAccessToken(String scope, String clientId) throws Exception {

		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "client_credentials");
		formData.add("client_id", clientId);
		formData.add("scope", scope);
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		headers.set("Authorization", "Basic " + new String(Base64.encode(String.format("%s:", clientId).getBytes())));

		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = serverRunning.postForMap("/sparklr2/oauth/token", headers, formData);
		assertEquals(HttpStatus.OK, response.getStatusCode());

		@SuppressWarnings("unchecked")
		OAuth2AccessToken accessToken = OAuth2AccessToken.valueOf(response.getBody());
		return accessToken;

	}

	private OAuth2AccessToken getResourceOwnerPasswordAccessToken(String scope, String clientId) throws Exception {
		MultiValueMap<String, String> formData = getTokenFormData(scope, clientId);

		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = serverRunning.postForMap("/sparklr2/oauth/token", formData);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));

		@SuppressWarnings("unchecked")
		OAuth2AccessToken accessToken = OAuth2AccessToken.valueOf(response.getBody());
		return accessToken;
	}

	private MultiValueMap<String, String> getTokenFormData(String scope, String clientId) {
		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "password");
		if (clientId != null) {
			formData.add("client_id", clientId);
		}
		formData.add("scope", scope);
		formData.add("username", "marissa");
		formData.add("password", "koala");
		return formData;
	}

}
