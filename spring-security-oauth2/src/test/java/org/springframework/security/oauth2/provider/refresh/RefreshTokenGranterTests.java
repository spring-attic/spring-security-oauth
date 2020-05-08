package org.springframework.security.oauth2.provider.refresh;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertTrue;

public class RefreshTokenGranterTests {

	private Authentication validUser = new UsernamePasswordAuthenticationToken("foo", "bar",
			Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));

	private AuthenticationManager authenticationManager = new AuthenticationManager() {
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			return validUser;
		}
	};

	private BaseClientDetails client = new BaseClientDetails("foo", "resource", "scope", "refresh_token", "ROLE_USER");

	private TokenStore tokenStore = new InMemoryTokenStore();
	private DefaultTokenServices providerTokenServices = new DefaultTokenServices();

	private ClientDetailsService clientDetailsService = new ClientDetailsService() {
		public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
			return client;
		}
	};

	private OAuth2RequestFactory requestFactory = new DefaultOAuth2RequestFactory(clientDetailsService);

	private OAuth2AccessToken accessToken;

	private TokenRequest validRefreshTokenRequest;

	@Before
	public void setUp() {
		String clientId = "client";
		BaseClientDetails clientDetails = new BaseClientDetails();
		clientDetails.setClientId(clientId);

		providerTokenServices.setTokenStore(tokenStore);
		providerTokenServices.setSupportRefreshToken(true);
		providerTokenServices.setAuthenticationManager(authenticationManager);
		// Create access token to refresh
		accessToken = providerTokenServices.createAccessToken(new OAuth2Authentication(requestFactory.createOAuth2Request(client, requestFactory.createTokenRequest(Collections.<String, String>emptyMap(), clientDetails)), validUser));
		validRefreshTokenRequest = createRefreshTokenRequest(accessToken.getRefreshToken().getValue());
	}

	private TokenRequest createRefreshTokenRequest(String refreshToken) {
		Map<String, String> parameters = new HashMap<String, String>();
		parameters.put("grant_type", "refresh_token");
		parameters.put("refresh_token", refreshToken);
		return requestFactory.createTokenRequest(parameters, client);
	}

	@Test
	public void testSunnyDay() {
		RefreshTokenGranter granter = new RefreshTokenGranter(providerTokenServices, clientDetailsService, requestFactory);
		OAuth2AccessToken token = granter.grant("refresh_token", validRefreshTokenRequest);
		OAuth2Authentication authentication = providerTokenServices.loadAuthentication(token.getValue());
		assertTrue(authentication.isAuthenticated());
	}

	@Test(expected = InvalidGrantException.class)
	public void testBadCredentials() {
		RefreshTokenGranter granter = new RefreshTokenGranter(providerTokenServices, clientDetailsService, requestFactory);
		granter.grant("refresh_token", createRefreshTokenRequest(accessToken.getRefreshToken().getValue() + "invalid_token"));
	}

	@Test(expected = InvalidClientException.class)
	public void testGrantTypeNotSupported() {
		RefreshTokenGranter granter = new RefreshTokenGranter(providerTokenServices, clientDetailsService, requestFactory);
		client.setAuthorizedGrantTypes(Collections.singleton("client_credentials"));
		granter.grant("refresh_token", validRefreshTokenRequest);
	}

	@Test(expected = InvalidGrantException.class)
	public void testAccountLocked() {
		providerTokenServices.setAuthenticationManager(new AuthenticationManager() {
			public Authentication authenticate(Authentication authentication) throws AuthenticationException {
				throw new LockedException("test");
			}
		});
		RefreshTokenGranter granter = new RefreshTokenGranter(providerTokenServices, clientDetailsService, requestFactory);
		granter.grant("refresh_token", validRefreshTokenRequest);
	}

	@Test(expected = InvalidGrantException.class)
	public void testUsernameNotFound() {
		providerTokenServices.setAuthenticationManager(new AuthenticationManager() {
			public Authentication authenticate(Authentication authentication) throws AuthenticationException {
				throw new UsernameNotFoundException("test");
			}
		});
		RefreshTokenGranter granter = new RefreshTokenGranter(providerTokenServices, clientDetailsService, requestFactory);
		granter.grant("refresh_token", validRefreshTokenRequest);
	}
}
