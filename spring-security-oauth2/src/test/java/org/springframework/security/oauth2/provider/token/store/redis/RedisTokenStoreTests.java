package org.springframework.security.oauth2.provider.token.store.redis;

import static org.junit.Assert.*;

import java.util.Date;
import java.util.UUID;

import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.RequestTokenFactory;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.TokenStoreBaseTests;

import redis.clients.jedis.JedisShardInfo;
import redis.embedded.RedisServer;

/**
 * @author efenderbosch
 */
public class RedisTokenStoreTests extends TokenStoreBaseTests {

	private RedisTokenStore tokenStore;
	private RedisServer redisServer;

	@Override
	public TokenStore getTokenStore() {
		return tokenStore;
	}

	@Before
	public void setup() throws Exception {
		try {
			redisServer = new RedisServer();
		} catch (Exception e) {
			Assume.assumeNoException("Embedded Redis not starting", e);
		}
		redisServer.start();
		JedisShardInfo shardInfo = new JedisShardInfo("localhost", redisServer.getPort());
		JedisConnectionFactory connectionFactory = new JedisConnectionFactory(shardInfo);
		tokenStore = new RedisTokenStore(connectionFactory);
	}

	@After
	public void tearDown() throws Exception {
		redisServer.stop();
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

}
