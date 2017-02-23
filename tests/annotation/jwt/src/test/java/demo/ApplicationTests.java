package demo;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.util.ReflectionTestUtils;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment=WebEnvironment.RANDOM_PORT)
public class ApplicationTests {

	@LocalServerPort
	private int port;

	@Autowired
	private AuthorizationServerTokenServices tokenServices;

	@Test
	public void tokenStoreIsJwt() {
		assertTrue("Wrong token store type: " + tokenServices,
				ReflectionTestUtils.getField(tokenServices, "tokenStore") instanceof JwtTokenStore);
	}

	@Test
	public void tokenKeyEndpointProtected() {
		assertEquals(HttpStatus.UNAUTHORIZED,
				new TestRestTemplate().getForEntity("http://localhost:" + port + "/oauth/token_key", String.class)
						.getStatusCode());
	}

	@Test
	public void tokenKeyEndpointWithSecret() {
		assertEquals(
				HttpStatus.OK,
				new TestRestTemplate("my-client-with-secret", "secret").getForEntity(
						"http://localhost:" + port + "/oauth/token_key", String.class).getStatusCode());
	}

}
