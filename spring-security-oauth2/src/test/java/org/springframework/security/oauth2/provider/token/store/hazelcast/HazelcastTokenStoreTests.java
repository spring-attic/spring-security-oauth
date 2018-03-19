package org.springframework.security.oauth2.provider.token.store.hazelcast;

import com.hazelcast.client.HazelcastClient;
import com.hazelcast.client.config.ClientConfig;
import com.hazelcast.client.config.ClientNetworkConfig;
import com.hazelcast.config.GroupConfig;
import com.hazelcast.core.HazelcastInstance;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.common.*;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.RequestTokenFactory;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.TokenStoreBaseTests;

import java.util.Collection;
import java.util.Date;
import java.util.UUID;

import static org.junit.Assert.*;

public class HazelcastTokenStoreTests extends TokenStoreBaseTests {

	private static HazelcastTokenStore tokenStore;

	@BeforeClass
	public static void beforeClass() {

		GroupConfig groupConfig = new GroupConfig()
				.setName("accounts")
				.setPassword("accounts-pass");

		ClientNetworkConfig networkConfig = new ClientNetworkConfig()
				.addAddress("127.0.0.1:5701");

		ClientConfig clientConfig = new ClientConfig()
				.setGroupConfig(groupConfig)
				.setNetworkConfig(networkConfig);

		HazelcastInstance instance = HazelcastClient.newHazelcastClient(clientConfig);

		tokenStore = new HazelcastTokenStore(instance);

	}

	@Override
	public TokenStore getTokenStore() {
		return tokenStore;
	}

	//<editor-fold desc="Copied from RedisTokenStoreTests">

	@Test
	public void testExpiringRefreshToken() throws InterruptedException {
		String refreshToken = UUID.randomUUID().toString();
		DefaultOAuth2RefreshToken expectedExpiringRefreshToken = new DefaultExpiringOAuth2RefreshToken(refreshToken,
				new Date(System.currentTimeMillis() + 1500));
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request(
				"id", false), new TestAuthentication("test2", false));
		getTokenStore().storeRefreshToken(expectedExpiringRefreshToken, expectedAuthentication);

		OAuth2RefreshToken actualExpiringRefreshToken = getTokenStore().readRefreshToken(refreshToken);
		assertEquals(expectedExpiringRefreshToken, actualExpiringRefreshToken);
		assertEquals(expectedAuthentication,
				getTokenStore().readAuthenticationForRefreshToken(expectedExpiringRefreshToken));

		// let the token expire
		Thread.sleep(1500);
		// now it should be gone
		assertNull(getTokenStore().readRefreshToken(refreshToken));
		assertNull(getTokenStore().readAuthenticationForRefreshToken(expectedExpiringRefreshToken));
	}

	@Test
	public void testExpiringAccessToken() throws InterruptedException {
		String accessToken = UUID.randomUUID().toString();
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request(
				"id", false), new TestAuthentication("test2", false));
		DefaultOAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken(accessToken);
		expectedOAuth2AccessToken.setExpiration(new Date(System.currentTimeMillis() + 1500));
		getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);

		OAuth2AccessToken actualOAuth2AccessToken = getTokenStore().readAccessToken(accessToken);
		assertEquals(expectedOAuth2AccessToken, actualOAuth2AccessToken);
		assertEquals(expectedAuthentication, getTokenStore().readAuthentication(expectedOAuth2AccessToken));

		// let the token expire
		Thread.sleep(1500);
		// now it should be gone
		assertNull(getTokenStore().readAccessToken(accessToken));
		assertNull(getTokenStore().readAuthentication(expectedOAuth2AccessToken));
	}

	@Test
	public void storeAccessTokenWithoutRefreshTokenRemoveAccessTokenVerifyTokenRemoved() {
		OAuth2Request request = RequestTokenFactory.createOAuth2Request("clientId", false);
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password");

		OAuth2AccessToken oauth2AccessToken = new DefaultOAuth2AccessToken("access-token-" + UUID.randomUUID());
		OAuth2Authentication oauth2Authentication = new OAuth2Authentication(request, authentication);

		tokenStore.storeAccessToken(oauth2AccessToken, oauth2Authentication);
		tokenStore.removeAccessToken(oauth2AccessToken);
		Collection<OAuth2AccessToken> oauth2AccessTokens = tokenStore.findTokensByClientId(request.getClientId());

		assertTrue(oauth2AccessTokens.isEmpty());
	}

	//</editor-fold>

}