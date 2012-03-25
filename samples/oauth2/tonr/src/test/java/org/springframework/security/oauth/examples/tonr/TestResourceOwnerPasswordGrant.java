package org.springframework.security.oauth.examples.tonr;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.Collections;

import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.context.OAuth2ClientContext;
import org.springframework.security.oauth2.client.context.OAuth2ClientContextHolder;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * @author Dave Syer
 */
public class TestResourceOwnerPasswordGrant {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	@After
	public void close() {
		OAuth2ClientContextHolder.clearContext();
	}

	@Test
	public void testConnectDirectlyToResourceServer() throws Exception {

		ResourceOwnerPasswordResourceDetails resource = new ResourceOwnerPasswordResourceDetails();

		resource.setAccessTokenUri(serverRunning.getUrl("/sparklr2/oauth/token"));
		resource.setClientId("my-trusted-client");
		resource.setId("sparklr");
		resource.setScope(Arrays.asList("trust"));
		resource.setUsername("marissa");
		resource.setPassword("koala");

		AccessTokenProviderChain provider = new AccessTokenProviderChain(Arrays.<AccessTokenProvider>asList(new ResourceOwnerPasswordAccessTokenProvider()));
		OAuth2AccessToken accessToken = provider.obtainAccessToken(resource, new AccessTokenRequest());

		OAuth2ClientContext context = new OAuth2ClientContext(Collections.singletonMap(resource.getId(), accessToken), new AccessTokenRequest());
		OAuth2ClientContextHolder.setContext(context);

		OAuth2RestTemplate template = new OAuth2RestTemplate(resource);
		String result = template.getForObject(serverRunning.getUrl("/sparklr2/photos/user/message"), String.class);
		// System.err.println(result);
		assertEquals("Hello, Trusted User marissa", result);

	}

}
