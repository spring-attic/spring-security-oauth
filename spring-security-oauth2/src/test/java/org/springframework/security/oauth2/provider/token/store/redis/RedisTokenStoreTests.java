package org.springframework.security.oauth2.provider.token.store.redis;

import org.junit.Before;
import org.junit.Test;
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * @author efenderbosch
 */
public class RedisTokenStoreTests extends TokenStoreBaseTests {

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

		JedisConnectionFactory connectionFactory;
		if (springDataRedis_2_0) {
			connectionFactory = new JedisConnectionFactory();
		} else {
			JedisShardInfo shardInfo = new JedisShardInfo("localhost");
			connectionFactory = new JedisConnectionFactory(shardInfo);
		}

		tokenStore = new RedisTokenStore(connectionFactory);
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

	@Test
	public void tokenExpirationWithParallelTokenStoring() throws InterruptedException {
		final Crate<Boolean> clientOn = new Crate<Boolean>(true);
		Runnable clientsSimulation = new Runnable() {
			@Override
			public void run() {
				while (clientOn.getObj()) {
					OAuth2Authentication auth = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request(
							"client_X", false), new TestAuthentication("user42", false));
					DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken(UUID.randomUUID().toString());
					accessToken.setExpiration(new Date(System.currentTimeMillis() + 1500));
					getTokenStore().storeAccessToken(accessToken, auth);

					// There is new token stored every half a second - our app is very used
					try {
						Thread.sleep(500);
					} catch (InterruptedException e) {
						e.printStackTrace();
						fail();
					}
				}
			}
		};

		// Start client simulation
		Thread clientsThread = new Thread(clientsSimulation);
		clientsThread.start();

		// Create and store our own token
		String accessToken = UUID.randomUUID().toString();
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request(
				"client_X", false), new TestAuthentication("user1", false));
		DefaultOAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken(accessToken);
		expectedOAuth2AccessToken.setExpiration(new Date(System.currentTimeMillis() + 1500));
		getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);

		// Should be possible to read the token
		OAuth2AccessToken actualOAuth2AccessToken = getTokenStore().readAccessToken(accessToken);
		assertEquals(expectedOAuth2AccessToken, actualOAuth2AccessToken);
		assertEquals(expectedAuthentication, getTokenStore().readAuthentication(expectedOAuth2AccessToken));
		assertNotNull(findAccessToken(getTokenStore().findTokensByClientId("client_X"), accessToken));
		assertNotNull(findAccessToken(getTokenStore().findTokensByClientIdAndUserName("client_X", "user1"), accessToken));

		// let the token expire
		Thread.sleep(1500);

		// now it should be gone
		assertNull(getTokenStore().readAccessToken(accessToken));
		assertNull(getTokenStore().readAuthentication(expectedOAuth2AccessToken));
		assertNull(findAccessToken(getTokenStore().findTokensByClientId("client_X"), accessToken));
		assertNull(findAccessToken(getTokenStore().findTokensByClientIdAndUserName("client_X", "user1"), accessToken));

		// Stop the client
		clientOn.setObj(false);
		clientsThread.join();

		// let clients token expire
		Thread.sleep(2000);
	}

	private OAuth2AccessToken findAccessToken(Collection<OAuth2AccessToken> tokens, String tokenValue) {
		for (OAuth2AccessToken token : tokens) {
			if (tokenValue.equals(token.getValue())) {
				return token;
			}
		}
		return null;
	}

	private static class Crate<E> {
		E obj;

		public Crate(final E obj) {
			this.obj = obj;
		}

		public E getObj() {
			return obj;
		}

		public void setObj(final E obj) {
			this.obj = obj;
		}
	}
}