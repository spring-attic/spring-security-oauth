package org.springframework.security.oauth2.provider;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.Arrays;
import java.util.Map;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class TestClientCredentialsProvider {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();
	
	/**
	 * tests the basic provider
	 */
	@Test
	public void testPostForToken() throws Exception {
		OAuth2AccessToken token = getClientCredentialsAccessToken("read", "my-client-with-registered-redirect");
		assertNull(token.getRefreshToken());		
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

}
