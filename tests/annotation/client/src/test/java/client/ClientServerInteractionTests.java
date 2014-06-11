package client;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.test.context.ActiveProfiles;

import sparklr.common.AbstractIntegrationTests;

/**
 * @author Dave Syer
 */
@SpringApplicationConfiguration(classes = { ClientApplication.class, CombinedApplication.class })
@ActiveProfiles("combined")
public class ClientServerInteractionTests extends AbstractIntegrationTests {

	@Autowired
	private AuthorizationCodeResourceDetails resource;

	private OAuth2RestOperations template;
	
	@Before
	public void init() {
		template = new OAuth2RestTemplate(resource, new DefaultOAuth2ClientContext());
	}

	@Test
	public void testForRedirectWithNoToken() throws Exception {
		try {
			template.getForObject(http.getUrl("/"), String.class);
			fail("Expected UserRedirectRequiredException");
		}
		catch (UserRedirectRequiredException e) {
			String message = e.getMessage();
			assertTrue("Wrong message: " + message,
					message.contains("A redirect is required to get the users approval"));
		}
	}

}
