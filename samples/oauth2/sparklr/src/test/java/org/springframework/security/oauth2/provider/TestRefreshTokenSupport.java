package org.springframework.security.oauth2.provider;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;

import java.util.Map;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class TestRefreshTokenSupport {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	/**
	 * tests a happy-day flow of the refresh token provider.
	 */
	@Test
	public void testHappyDay() throws Exception {

		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "password");
		formData.add("client_id", "my-trusted-client");
		formData.add("scope", "read");
		formData.add("username", "marissa");
		formData.add("password", "koala");
		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = serverRunning.postForMap("/sparklr2/oauth/token", formData);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));

		@SuppressWarnings("unchecked")
		OAuth2AccessToken accessToken = OAuth2AccessToken.valueOf(response.getBody());

		// now try and use the token to access a protected resource.

		// first make sure the resource is actually protected.
		assertNotSame(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/photos?format=json"));

		// now make sure an authorized request is valid.
		HttpHeaders headers = new HttpHeaders();
		headers.set("Authorization", String.format("%s %s", OAuth2AccessToken.BEARER_TYPE, accessToken.getValue()));
		assertEquals(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/photos?format=json", headers));

		// now use the refresh token to get a new access token.
		assertNotNull(accessToken.getRefreshToken());
		formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "refresh_token");
		formData.add("client_id", "my-trusted-client");
		formData.add("refresh_token", accessToken.getRefreshToken().getValue());
		response = serverRunning.postForMap("/sparklr2/oauth/token", formData);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));
		@SuppressWarnings("unchecked")
		OAuth2AccessToken newAccessToken = OAuth2AccessToken.valueOf(response.getBody());
		assertFalse(newAccessToken.getValue().equals(accessToken.getValue()));

		// make sure the new access token can be used.
		headers = new HttpHeaders();
		headers.set("Authorization", String.format("%s %s", OAuth2AccessToken.BEARER_TYPE, newAccessToken.getValue()));
		assertEquals(HttpStatus.OK, serverRunning.getStatusCode("/sparklr2/photos?format=json", headers));

		// make sure the old access token isn't valid anymore.
		headers.set("Authorization", String.format("%s %s", OAuth2AccessToken.BEARER_TYPE, accessToken.getValue()));
		assertEquals(HttpStatus.UNAUTHORIZED, serverRunning.getStatusCode("/sparklr2/photos?format=json", headers));
	}
}
