package org.springframework.security.oauth2.provider.token.store.redis;

import org.junit.Before;
import org.junit.Test;

import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.RequestTokenFactory;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.TokenStoreBaseTests;
import org.springframework.util.ClassUtils;
import redis.clients.jedis.JedisShardInfo;

import java.util.Collection;
import java.util.Date;
import java.util.UUID;

import static org.junit.Assert.*;

/**
 * @author efenderbosch
 */
public class RedisTokenStoreTests extends TokenStoreBaseTests {

	private JedisConnectionFactory connectionFactory;
	private RedisTokenStoreSerializationStrategy serializationStrategy = new JdkSerializationStrategy();
	private RedisTokenStore tokenStore;

	@Override
	public TokenStore getTokenStore() {
		return tokenStore;
	}

	@Before
	public void setup() throws Exception {
		boolean springDataRedis_2_0 = ClassUtils.isPresent(
				"org.springframework.data.redis.connection.RedisStandaloneConfiguration",
				this.getClass().getClassLoader());

		if (springDataRedis_2_0) {
			connectionFactory = new JedisConnectionFactory();
		} else {
			JedisShardInfo shardInfo = new JedisShardInfo("localhost");
			connectionFactory = new JedisConnectionFactory(shardInfo);
		}

		serializationStrategy = new JdkSerializationStrategy();
		tokenStore = new RedisTokenStore(connectionFactory);
		tokenStore.setSerializationStrategy(serializationStrategy);
	}

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

	// gh-572
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

	// gh-1836
	@Test
	public void storeAccessTokenWithRefreshTokenRemoveRefreshTokenAndAccessTokenVerifyTokenRemoved() {
		OAuth2Request request = RequestTokenFactory.createOAuth2Request("clientId", false);
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password");

		DefaultOAuth2AccessToken oauth2AccessToken = new DefaultOAuth2AccessToken(
				"access-token-" + UUID.randomUUID());
		DefaultOAuth2RefreshToken oauth2RefreshToken = new DefaultOAuth2RefreshToken(
				"refresh-token-" + UUID.randomUUID());
		oauth2AccessToken.setRefreshToken(oauth2RefreshToken);

		OAuth2Authentication oauth2Authentication = new OAuth2Authentication(request, authentication);

		tokenStore.storeAccessToken(oauth2AccessToken, oauth2Authentication);
		String accessTokenValue = getValue("refresh_to_access:" + oauth2RefreshToken.getValue());
		assertEquals(accessTokenValue, oauth2AccessToken.getValue());
		String refreshTokenValue = getValue("access_to_refresh:" + oauth2AccessToken.getValue());
		assertEquals(refreshTokenValue, oauth2RefreshToken.getValue());

		tokenStore.removeRefreshToken(oauth2RefreshToken);
		accessTokenValue = getValue("refresh_to_access:" + oauth2RefreshToken.getValue());
		assertNull("Key refresh_to_access was not deleted!", accessTokenValue);
		refreshTokenValue = getValue("access_to_refresh:" + oauth2AccessToken.getValue());
		assertNull("Key access_to_refresh was not deleted!", refreshTokenValue);

		tokenStore.removeAccessToken(oauth2AccessToken);

		Collection<OAuth2AccessToken> oauth2AccessTokens = tokenStore.findTokensByClientId(request.getClientId());
		assertTrue(oauth2AccessTokens.isEmpty());
	}

	private String getValue(String key) {
		RedisConnection conn = connectionFactory.getConnection();
		try {
			byte[] value = conn.get(key.getBytes());
			return serializationStrategy.deserializeString(value);
		}
		finally {
			conn.close();
		}
	}
}