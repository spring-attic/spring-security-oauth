package demo;

import static org.junit.Assert.assertEquals;

import java.util.Map;

import org.junit.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import sparklr.common.AbstractClientCredentialsProviderTests;

/**
 * @author Dave Syer
 */
@SpringBootTest(classes=Application.class, properties="server.servlet_path:/server", webEnvironment=WebEnvironment.RANDOM_PORT)
public class ServletPathClientCredentialsProviderTests extends AbstractClientCredentialsProviderTests {
	
	@Test
	public void testTokenKey() throws Exception {
		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = new TestRestTemplate("my-client-with-secret", "secret").getForEntity(
				http.getUrl(tokenKeyPath()), Map.class);
		// This app has no token key.
		assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
	}

}
