package org.springframework.security.oauth2.provider;

import static org.junit.Assert.assertNull;

import java.util.Arrays;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.TestClientCredentialsProvider.ClientCredentials;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
@OAuth2ContextConfiguration(ClientCredentials.class)
public class TestClientCredentialsProvider {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();
	
	@Rule
	public OAuth2ContextSetup context = OAuth2ContextSetup.standard(serverRunning);
	
	/**
	 * tests the basic provider
	 */
	@Test
	public void testPostForToken() throws Exception {
		OAuth2AccessToken token = context.getAccessToken();
		assertNull(token.getRefreshToken());		
	}
	
	static class ClientCredentials extends ClientCredentialsResourceDetails {
		public ClientCredentials(Object target) {
			setClientId("my-client-with-registered-redirect");
			setScope(Arrays.asList("read"));
			setId(getClientId());
			TestClientCredentialsProvider test = (TestClientCredentialsProvider) target;
			setAccessTokenUri(test.serverRunning.getUrl("/sparklr2/oauth/token"));
		}
	}

}
