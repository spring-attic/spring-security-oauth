package org.springframework.security.oauth2.provider.token.store;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.RequestTokenFactory;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisShardInfo;
import redis.embedded.RedisServer;

import java.util.Collection;
import java.util.Date;

import static org.junit.Assert.*;
import static redis.clients.jedis.Protocol.DEFAULT_PORT;

/**
 * @author Maxim Pedich
 */
public class RedisTokenStoreTests extends TokenStoreBaseTests {

	private static final String ALL_KEYS = "*";
	private static final String HOST = "localhost";
	private RedisTokenStore tokenStore;
	private RedisServer redisServer;
	private Jedis jedis;

	@Override
	public RedisTokenStore getTokenStore() {
		return tokenStore;
	}

	@Before
	public void setUp() throws Exception {
		redisServer = new RedisServer(DEFAULT_PORT);
		redisServer.start();
		jedis = new Jedis(HOST, DEFAULT_PORT);
		jedis.connect();
		JedisShardInfo shardInfo = new JedisShardInfo(HOST, DEFAULT_PORT);
		RedisConnectionFactory connectionFactory = new JedisConnectionFactory(shardInfo);
		tokenStore = new RedisTokenStore(connectionFactory);
	}

	@After
	public void tearDown() throws Exception {
		jedis.flushDB();
		jedis.disconnect();
		redisServer.stop();
	}

	@Test
	public void testRemoveAccessTokenUsingRefreshToken() {
		OAuth2RefreshToken expectedExpiringRefreshToken = new DefaultExpiringOAuth2RefreshToken("testRefreshToken",
																								new Date());
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(
				RequestTokenFactory.createOAuth2Request("id", false), new TestAuthentication("test2", false));
		DefaultOAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken("testAccessToken");
		expectedOAuth2AccessToken.setRefreshToken(expectedExpiringRefreshToken);
		getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);

		getTokenStore().removeAccessTokenUsingRefreshToken(expectedExpiringRefreshToken);

		assertNull(getTokenStore().readRefreshToken("testRefreshToken"));
		assertNull(getTokenStore().readAccessToken("testAccessToken"));
	}

	@Test
	public void testRemoveAllKeysAccessToken() {
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request(
				"id", false), new TestAuthentication("test2", false));
		DefaultOAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken("testToken");
		expectedOAuth2AccessToken.setRefreshToken(new DefaultExpiringOAuth2RefreshToken("testRefreshToken", new Date()));

		getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);
		assertFalse(jedis.keys(ALL_KEYS).isEmpty());

		getTokenStore().removeAccessToken(expectedOAuth2AccessToken);
		assertTrue(jedis.keys(ALL_KEYS).isEmpty());
	}

	@Test
	public void testRemoveAllKeysRefreshToken() {
		OAuth2RefreshToken expectedExpiringRefreshToken = new DefaultExpiringOAuth2RefreshToken("testRefreshToken",
																								new Date());
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(
				RequestTokenFactory.createOAuth2Request("id", false), new TestAuthentication("test2", false));

		getTokenStore().storeRefreshToken(expectedExpiringRefreshToken, expectedAuthentication);
		assertFalse(jedis.keys(ALL_KEYS).isEmpty());

		getTokenStore().removeRefreshToken(expectedExpiringRefreshToken);
		assertTrue(jedis.keys(ALL_KEYS).isEmpty());
	}

	@Test
	public void testFindAccessTokensByClientIdAfterRemoveAccessToken() {
		String clientId = "clientId";
		OAuth2Authentication expectedAuthentication1 = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request(
				clientId, false), new TestAuthentication("test1", false));
		OAuth2AccessToken expectedOAuth2AccessToken1 = new DefaultOAuth2AccessToken("testToken1");
		OAuth2Authentication expectedAuthentication2 = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request(
				clientId, false), new TestAuthentication("test2", false));
		OAuth2AccessToken expectedOAuth2AccessToken2 = new DefaultOAuth2AccessToken("testToken2");
		getTokenStore().storeAccessToken(expectedOAuth2AccessToken1, expectedAuthentication1);
		getTokenStore().storeAccessToken(expectedOAuth2AccessToken2, expectedAuthentication2);

		Collection<OAuth2AccessToken> actualOAuth2AccessTokens = getTokenStore().findTokensByClientId(clientId);
		assertEquals(2, actualOAuth2AccessTokens.size());

		getTokenStore().removeAccessToken(expectedOAuth2AccessToken1);

		actualOAuth2AccessTokens = getTokenStore().findTokensByClientId(clientId);
		assertEquals(1, actualOAuth2AccessTokens.size());
	}

}
