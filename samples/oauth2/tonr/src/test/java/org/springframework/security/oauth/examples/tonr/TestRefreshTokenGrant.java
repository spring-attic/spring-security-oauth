package org.springframework.security.oauth.examples.tonr;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
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
public class TestRefreshTokenGrant {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	private AccessTokenProviderChain provider = new AccessTokenProviderChain(
			Arrays.<AccessTokenProvider> asList(new ResourceOwnerPasswordAccessTokenProvider()));

	private OAuth2AccessToken existingToken;

	private ResourceOwnerPasswordResourceDetails resource;

	@Before
	public void setup() {
		resource = new ResourceOwnerPasswordResourceDetails();

		resource.setAccessTokenUri(serverRunning.getUrl("/sparklr2/oauth/token"));
		resource.setClientId("my-trusted-client");
		resource.setId("sparklr");
		resource.setScope(Arrays.asList("trust"));
		resource.setUsername("marissa");
		resource.setPassword("koala");

		existingToken = provider.obtainAccessToken(resource, new AccessTokenRequest());
		existingToken.setExpiration(new Date(0L));

		SecurityContextImpl context = new SecurityContextImpl();
		context.setAuthentication(new TestingAuthenticationToken("marissa", "koala", "ROLE_USER"));
		SecurityContextHolder.setContext(context);

	}

	@After
	public void close() {
		OAuth2ClientContextHolder.clearContext();
		SecurityContextHolder.clearContext();
	}

	@Test
	public void testConnectDirectlyToResourceServer() throws Exception {

		assertNotNull(existingToken.getRefreshToken());
		// It won't be expired on the server, but we can force the client to refresh it
		assertTrue(existingToken.isExpired());

		AccessTokenRequest request = new AccessTokenRequest();
		request.setExistingToken(existingToken);
		OAuth2AccessToken accessToken = provider.obtainAccessToken(resource, request);

		OAuth2ClientContext context = new OAuth2ClientContext(Collections.singletonMap(resource.getId(), accessToken),
				request);
		OAuth2ClientContextHolder.setContext(context);

		OAuth2RestTemplate template = new OAuth2RestTemplate(resource);
		String result = template.getForObject(serverRunning.getUrl("/sparklr2/photos/user/message"), String.class);
		assertEquals("Hello, Trusted User marissa", result);

		assertFalse("Tokens match so there was no refresh", existingToken.equals(accessToken));

	}

}
