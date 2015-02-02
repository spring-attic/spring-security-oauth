package demo;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;

import org.junit.Test;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;

import sparklr.common.AbstractResourceOwnerPasswordProviderTests;

/**
 * @author Dave Syer
 */
@SpringApplicationConfiguration(classes=Application.class)
public class ResourceOwnerPasswordProviderTests extends AbstractResourceOwnerPasswordProviderTests {

	@Test
	@OAuth2ContextConfiguration(OtherResourceOwner.class)
	public void testTokenObtainedWithHeaderAuthenticationAndOtherResource() throws Exception {
		assertEquals(HttpStatus.OK, http.getStatusCode("/"));
	}

	static class OtherResourceOwner extends ResourceOwner implements DoNotOverride {
		public OtherResourceOwner(Object target) {
			super(target);
			setClientId("my-other-client-with-secret");
			setClientSecret("secret");
			setScope(Arrays.asList("trust"));
		}
	}

}
