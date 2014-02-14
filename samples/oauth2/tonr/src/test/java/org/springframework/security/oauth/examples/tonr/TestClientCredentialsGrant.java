package org.springframework.security.oauth.examples.tonr;


import static org.junit.Assert.assertEquals;

import java.util.Arrays;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.web.client.RestTemplate;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class TestClientCredentialsGrant {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	@Test
	public void testConnectDirectlyToResourceServer() throws Exception {

		ClientCredentialsResourceDetails resource = new ClientCredentialsResourceDetails();

		resource.setAccessTokenUri(serverRunning.getUrl("/sparklr2/oauth/token"));
		resource.setClientId("my-client-with-registered-redirect");
		resource.setId("sparklr");
		resource.setScope(Arrays.asList("trust"));

		ClientCredentialsAccessTokenProvider provider = new ClientCredentialsAccessTokenProvider();
		OAuth2AccessToken accessToken = provider.obtainAccessToken(resource, new DefaultAccessTokenRequest());

		OAuth2RestTemplate template = new OAuth2RestTemplate(resource, new DefaultOAuth2ClientContext(accessToken));
		String result = template.getForObject(serverRunning.getUrl("/sparklr2/photos/trusted/message"), String.class);
		assertEquals("Hello, Trusted Client", result);

	}

	@Test
	public void testConnectThroughClientApp() throws Exception {

		// tonr is a trusted client of sparklr for this resource
		RestTemplate template = new RestTemplate();
		String result = template.getForObject(serverRunning.getUrl("/tonr2/trusted/message"), String.class);
		// System.err.println(result);
		assertEquals("{\"message\":\"Hello, Trusted Client\"}", result);

	}

}
