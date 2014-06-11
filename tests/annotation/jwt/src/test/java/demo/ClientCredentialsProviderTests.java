package demo;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Map;

import org.junit.Test;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;

import sparklr.common.AbstractClientCredentialsProviderTests;

/**
 * @author Dave Syer
 */
@SpringApplicationConfiguration(classes = Application.class)
public class ClientCredentialsProviderTests extends AbstractClientCredentialsProviderTests {

	/**
	 * tests the check_token endpoint
	 */
	@Test
	@OAuth2ContextConfiguration(ClientCredentials.class)
	public void testCheckToken() throws Exception {
		OAuth2AccessToken token = context.getAccessToken();
		HttpHeaders headers = new HttpHeaders();
		headers.set("Content-Type", MediaType.APPLICATION_FORM_URLENCODED_VALUE);
		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = new TestRestTemplate("my-client-with-secret", "secret").exchange(http
				.getUrl(checkTokenPath()), HttpMethod.POST,
				new HttpEntity<String>("token=" + token.getValue(), headers), Map.class);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		@SuppressWarnings("unchecked")
		Map<String, Object> map = (Map<String, Object>) response.getBody();
		assertTrue(map.containsKey(AccessTokenConverter.EXP));
		assertEquals("my-client-with-secret", map.get(AccessTokenConverter.CLIENT_ID));
	}

	@Test
	public void testTokenKey() throws Exception {
		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = new TestRestTemplate("my-client-with-secret", "secret").getForEntity(
				http.getUrl(tokenKeyPath()), Map.class);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		@SuppressWarnings("unchecked")
		Map<String, Object> map = (Map<String, Object>) response.getBody();
		assertTrue(map.containsKey("alg"));
	}

}
