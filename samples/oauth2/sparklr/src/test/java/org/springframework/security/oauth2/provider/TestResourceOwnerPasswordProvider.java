package org.springframework.security.oauth2.provider;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class TestResourceOwnerPasswordProvider {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	/**
	 * tests a happy-day flow of the native application provider.
	 */
	@Test
	public void testTokenObtainedWithFormAuthentication() throws Exception {

		OAuth2AccessToken accessToken = getAccessToken("read", "my-trusted-client");

		// first make sure the resource is actually protected.
		assertNotSame(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/photos?format=json"));

		// now make sure an authorized request is valid.
		HttpHeaders headers = new HttpHeaders();
		headers.set("Authorization", String.format("%s %s", OAuth2AccessToken.BEARER_TYPE, accessToken.getValue()));
		assertEquals(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/photos?format=json", headers));
	}

	/**
	 * tests a happy-day flow of the native application provider.
	 */
	@Test
	public void testTokenObtainedWithHeaderAuthentication() throws Exception {

		MultiValueMap<String, String> formData = getTokenFormData("read");

		HttpHeaders headers = new HttpHeaders();
		headers.set("Authorization",
				String.format("Basic %s", new String(Base64.encode("my-trusted-client:".getBytes("UTF-8")), "UTF-8")));
		headers.setAccept(Arrays.asList(MediaType.ALL));

		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = serverRunning.postForMap("/sparklr2/oauth/token", headers, formData);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));

		String accessToken = (String) response.getBody().get("access_token");
		assertNotNull(accessToken);
	}

	/**
	 * tests a happy-day flow of the native application profile.
	 */
	@Test
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public void testSecretRequired() throws Exception {
		MultiValueMap<String, String> formData = getTokenFormData("read", "my-trusted-client-with-secret");
		ResponseEntity<Map> response = serverRunning.postForMap("/sparklr2/oauth/token", formData);
		assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
		assertEquals(MediaType.APPLICATION_JSON, response.getHeaders().getContentType());
		OAuth2Exception oauthException = OAuth2Exception.valueOf(response.getBody());
		assertTrue("Should be an instance of InvalidClientException. Got " + oauthException,
				oauthException instanceof InvalidClientException);
	}

	/**
	 * tests a happy-day flow of the native application provider.
	 */
	@Test
	public void testSecretProvided() throws Exception {
		MultiValueMap<String, String> formData = getTokenFormData("read", "my-trusted-client-with-secret");
		formData.add("client_secret", "somesecret");
		ResponseEntity<String> response = serverRunning.postForString("/sparklr2/oauth/token", formData);
		assertEquals(HttpStatus.OK, response.getStatusCode());
	}

	/**
	 * tests a happy-day flow of the native application provider.
	 */
	@Test
	public void testSecretProvidedInHeader() throws Exception {
		MultiValueMap<String, String> formData = getTokenFormData("read");
		HttpHeaders headers = new HttpHeaders();
		headers.set("Authorization",
				"Basic " + new String(Base64.encode("my-trusted-client-with-secret:somesecret".getBytes())));
		headers.setAccept(Arrays.asList(MediaType.ALL));
		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = serverRunning.postForMap("/sparklr2/oauth/token", headers, formData);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertTrue("Wrong body: " + response.getBody(), response.getBody().containsKey("access_token"));
	}

	/**
	 * tests that an error occurs if you attempt to use username/password creds for a non-password grant type.
	 */
	@Test
	public void testInvalidGrantType() throws Exception {

		MultiValueMap<String, String> formData = getTokenFormData("read");
		formData.add("client_id", "my-untrusted-client-with-registered-redirect");
		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = serverRunning.postForMap("/sparklr2/oauth/token", formData);
		assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());

		List<String> newCookies = response.getHeaders().get("Set-Cookie");
		if (newCookies != null && !newCookies.isEmpty()) {
			fail("No cookies should be set. Found: " + newCookies.get(0) + ".");
		}

		@SuppressWarnings("unchecked")
		OAuth2Exception error = OAuth2Exception.valueOf(response.getBody());
		assertEquals("invalid_grant", error.getOAuth2ErrorCode());
	}

	/**
	 * tests a happy-day flow of the native application provider.
	 */
	@Test
	public void testClientRoleBasedSecurity() throws Exception {

		OAuth2AccessToken accessToken = getAccessToken("trust", "my-trusted-client");

		// now try and use the token to access a protected resource.

		// first make sure the resource is actually protected.
		assertEquals(HttpStatus.UNAUTHORIZED, serverRunning.getStatusCode("/sparklr2/photos/user/message"));

		// now make sure an authorized request is valid.
		HttpHeaders headers = new HttpHeaders();
		headers.set("Authorization", String.format("%s %s", OAuth2AccessToken.BEARER_TYPE, accessToken.getValue()));
		assertEquals(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/photos/user/message", headers));
	}

	/**
	 * tests a happy-day flow of the native application provider.
	 */
	@Test
	public void testUnsupportedMediaType() throws Exception {
		OAuth2AccessToken accessToken = getAccessToken("trust", "my-trusted-client");
		// now try and use the token to access a protected resource.
		HttpHeaders headers = new HttpHeaders();
		headers.set("Authorization", String.format("%s %s", OAuth2AccessToken.BEARER_TYPE, accessToken.getValue()));
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

	private OAuth2AccessToken getAccessToken(String scope, String clientId) throws Exception {
		MultiValueMap<String, String> formData = getTokenFormData(scope, clientId);

		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = serverRunning.postForMap("/sparklr2/oauth/token", formData);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));

		@SuppressWarnings("unchecked")
		OAuth2AccessToken accessToken = OAuth2AccessToken.valueOf(response.getBody());
		return accessToken;
	}

	private MultiValueMap<String, String> getTokenFormData(String scope) {
		return getTokenFormData(scope, null);
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
