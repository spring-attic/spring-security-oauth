package demo;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.net.URI;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

import sparklr.common.AbstractClientCredentialsProviderTests;

/**
 * Integration tests using the {@link HardCodedAuthenticationFilter}.
 * 
 * One client should be able to use the token endpoint /oauth/token by only providing its client_id as a parameter.
 * 
 * @author michaeltecourt
 */
@SpringApplicationConfiguration(classes = Application.class)
public class ClientCredentialsProviderTests extends AbstractClientCredentialsProviderTests {

	protected URI tokenUri;

	@Before
	public void setUp() {
		tokenUri = URI.create(http.getUrl("/oauth/token"));
	}

	/**
	 * No Basic authentication provided, only the hard coded client_id.
	 */
	@Test
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public void testHardCodedAuthenticationFineClient() {

		RestTemplate restTemplate = new RestTemplate();
		MultiValueMap<String, String> params = new LinkedMultiValueMap<String, String>();
		params.add("grant_type", "client_credentials");
		params.add("client_id", "my-client-with-secret");
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		RequestEntity<MultiValueMap<String, String>> req = new RequestEntity<MultiValueMap<String, String>>(params,
				headers, HttpMethod.POST, tokenUri);

		ResponseEntity<Map> response = restTemplate.exchange(req, Map.class);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		Map<String, String> body = response.getBody();
		String accessToken = body.get("access_token");
		assertNotNull(accessToken);
	}

	@Test
	public void testHardCodedAuthenticationWrongClient() {

		RestTemplate restTemplate = new RestTemplate();
		MultiValueMap<String, String> params = new LinkedMultiValueMap<String, String>();
		params.add("grant_type", "client_credentials");
		params.add("client_id", "my-trusted-client");
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		RequestEntity<MultiValueMap<String, String>> req = new RequestEntity<MultiValueMap<String, String>>(params,
				headers, HttpMethod.POST, tokenUri);

		try {
			restTemplate.exchange(req, Map.class);
			fail("Expected HTTP 401");
		}
		catch (HttpStatusCodeException e) {
			assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
		}
	}
}
