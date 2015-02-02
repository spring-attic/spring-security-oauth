package demo;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;

import sparklr.common.AbstractResourceOwnerPasswordProviderTests;

/**
 * @author Dave Syer
 */
@SpringApplicationConfiguration(classes = Application.class)
public class ResourceOwnerPasswordProviderTests extends AbstractResourceOwnerPasswordProviderTests {

	protected String getPassword() {
		return "secret";
	}

	protected String getUsername() {
		return "dave";
	}
	
	@Test
	@OAuth2ContextConfiguration(JdbcResourceOwner.class)
	public void testTokenObtainedWithHeaderAuthenticationAndJdbcUser() throws Exception {
		assertEquals(HttpStatus.OK, http.getStatusCode("/admin/beans"));
		int expiry = context.getAccessToken().getExpiresIn();
		assertTrue("Expiry not overridden in config: " + expiry, expiry < 1000);
	}

	static class JdbcResourceOwner extends ResourceOwner implements DoNotOverride {
		public JdbcResourceOwner(Object target) {
			super(target);
			// The other tests all use SecurityProperties which should be the parent authentication manager
			setUsername("dave");
			setPassword("secret");
		}
	}

}
