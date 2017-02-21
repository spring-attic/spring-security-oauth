package demo;

import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.test.BeforeOAuth2Context;
import org.springframework.security.oauth2.common.AuthenticationScheme;

import sparklr.common.AbstractResourceOwnerPasswordProviderTests;

/**
 * @author Dave Syer
 */
public class ResourceOwnerPasswordProviderTests extends
		AbstractResourceOwnerPasswordProviderTests {

	@BeforeOAuth2Context
	public void tweakClientAuthentication() {
		((BaseOAuth2ProtectedResourceDetails)context.getResource())
				.setClientAuthenticationScheme(AuthenticationScheme.form);
	}

}
