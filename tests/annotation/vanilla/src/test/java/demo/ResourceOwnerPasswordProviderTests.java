package demo;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;

import sparklr.common.AbstractResourceOwnerPasswordProviderTests;

/**
 * @author Dave Syer
 */
@SpringApplicationConfiguration(classes=Application.class)
public class ResourceOwnerPasswordProviderTests extends AbstractResourceOwnerPasswordProviderTests {

	@Test
	@OAuth2ContextConfiguration(ResourceOwner.class)
	public void testCheckToken() throws Exception {
		TestRestTemplate template = new TestRestTemplate("my-trusted-client", "");
		ResponseEntity<String> response = template.getForEntity(http.getUrl("/oauth/check_token?token={token}"), String.class, context.getAccessToken().getValue());
		assertEquals(HttpStatus.OK, response.getStatusCode());
	}

}
