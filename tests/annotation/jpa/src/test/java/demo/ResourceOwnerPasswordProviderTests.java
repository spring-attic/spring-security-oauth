package demo;

import org.junit.Test;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import sparklr.common.AbstractResourceOwnerPasswordProviderTests;

import static org.junit.Assert.assertEquals;

/**
 * @author Dave Syer
 */
public class ResourceOwnerPasswordProviderTests extends AbstractResourceOwnerPasswordProviderTests {

	@Test
	@OAuth2ContextConfiguration(ResourceOwner.class)
	public void testCheckToken() throws Exception {
		TestRestTemplate template = new TestRestTemplate("my-trusted-client", "");
		ResponseEntity<String> response = template.getForEntity(http.getUrl("/oauth/check_token?token={token}"), String.class, context.getAccessToken().getValue());
		assertEquals(HttpStatus.METHOD_NOT_ALLOWED, response.getStatusCode());
	}

	/**
	 * Note: This test is to check the POST request call to CheckTokenEndpoint. 
	 * The main intention is to avoid passing parameters as part of the URL /oauth/check_token. Example: /oauth/check_token?token={token}
	 * Instead making sure that the URL /oauth/check_token accepts only POST request calls so that parameters can be part of request body.
	*/	
	@Test
	@OAuth2ContextConfiguration(ResourceOwner.class)
	public void testCheckTokenPostRequestCall() throws Exception {
		TestRestTemplate template = new TestRestTemplate("my-trusted-client", "");
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("token", context.getAccessToken().getValue());
		HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
		ResponseEntity<String> response = template.postForEntity(http.getUrl("/oauth/check_token"), request, String.class);
		assertEquals(HttpStatus.OK, response.getStatusCode());
	}
	
}
