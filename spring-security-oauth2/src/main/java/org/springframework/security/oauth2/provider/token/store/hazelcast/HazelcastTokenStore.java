package org.springframework.security.oauth2.provider.token.store.hazelcast;

import com.hazelcast.client.HazelcastClient;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.IMap;
import com.sun.istack.internal.Nullable;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.TokenStore;

import java.util.Collection;
import java.util.Date;
import java.util.concurrent.TimeUnit;

/**
 * Implementation of token services that stores tokens in hazelcast.
 *
 * @author Ryan Heaton
 * @author Luke Taylor
 * @author Dave Syer
 */
public class HazelcastTokenStore implements TokenStore {

	private IMap<String, OAuth2AccessToken> accessTokenStore;
	private IMap<String, OAuth2RefreshToken> refreshTokenStore;

	private final HazelcastInstance hazelcastInstance;
	private IMap<String, String> accessTokenToRefreshTokenStore;
	private IMap<String, OAuth2Authentication> authenticationStore;
	private IMap<String, OAuth2Authentication> refreshTokenAuthenticationStore;
	private IMap<String, String> refreshTokenToAccessTokenStore;

	private AuthenticationKeyGenerator authenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();
	private IMap<String, OAuth2AccessToken> authenticationToAccessTokenStore;

	public HazelcastTokenStore(String instanceName) {
		this.hazelcastInstance = HazelcastClient.getHazelcastClientByName(instanceName);
		initialize();
	}

	public HazelcastTokenStore(HazelcastInstance instance) {
		this.hazelcastInstance = instance;
		initialize();
	}

	private void initialize() {

		accessTokenStore = map("accessTokenStore");
		authenticationToAccessTokenStore = map("authenticationToAccessTokenStore");

		refreshTokenStore = map("refreshTokenStore");
		authenticationStore = map("authenticationStore");
		refreshTokenAuthenticationStore = map("refreshTokenAuthenticationStore");
		refreshTokenToAccessTokenStore = map("refreshTokenToAccessTokenStore");
		accessTokenToRefreshTokenStore = map("accessTokenToRefreshTokenStore");

	}

	@Override
	public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
		String key = authenticationKeyGenerator.extractKey(authentication);
		OAuth2AccessToken accessToken = authenticationToAccessTokenStore.get(key);
		if (accessToken != null && !key.equals(authenticationKeyGenerator.extractKey(readAuthentication(accessToken.getValue())))) {
			// Keep the stores consistent (maybe the same user is
			// represented by this authentication but the details
			// have changed)
			storeAccessToken(accessToken, authentication);
		}
		return accessToken;
	}

	@Override
	public OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
		return readAuthentication(token.getValue());
	}

	@Override
	public OAuth2Authentication readAuthentication(String token) {
		return this.authenticationStore.get(token);
	}

	@Override
	public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken token) {
		return readAuthenticationForRefreshToken(token.getValue());
	}

	@Override
	public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {

		Integer expirySeconds = null;
		if (token.getExpiration() != null)
			expirySeconds = token.getExpiresIn();

		putRespectExpirationSeconds(accessTokenStore, token.getValue(), token, expirySeconds);
		putRespectExpirationSeconds(authenticationStore, token.getValue(), authentication, expirySeconds);
		putRespectExpirationSeconds(authenticationToAccessTokenStore, authenticationKeyGenerator.extractKey(authentication), token, expirySeconds);

		if (!authentication.isClientOnly())
			putRespectExpirationSeconds(map(getApprovalKey(authentication)), token.getValue(), token, expirySeconds);

		putRespectExpirationSeconds(map(authentication.getOAuth2Request().getClientId()), token.getValue(), token, expirySeconds);

		if (token.getRefreshToken() != null && token.getRefreshToken().getValue() != null) {
			putRespectExpirationSeconds(refreshTokenToAccessTokenStore, token.getRefreshToken().getValue(), token.getValue(), expirySeconds);
			putRespectExpirationSeconds(accessTokenToRefreshTokenStore, token.getValue(), token.getRefreshToken().getValue(), expirySeconds);
		}
	}

	@Override
	public void removeAccessToken(OAuth2AccessToken accessToken) {
		removeAccessToken(accessToken.getValue());
	}

	@Override
	public OAuth2AccessToken readAccessToken(String tokenValue) {
		return this.accessTokenStore.get(tokenValue);
	}

	@Override
	public void storeRefreshToken(OAuth2RefreshToken token, OAuth2Authentication authentication) {

		Integer expirySeconds = null;
		if (token instanceof ExpiringOAuth2RefreshToken) {
			Date expiration = ((ExpiringOAuth2RefreshToken) token).getExpiration();
			if (expiration != null)
				expirySeconds = Long.valueOf((expiration.getTime() - System.currentTimeMillis()) / 1000L).intValue();
		}

		putRespectExpirationSeconds(refreshTokenStore, token.getValue(), token, expirySeconds);
		putRespectExpirationSeconds(refreshTokenAuthenticationStore, token.getValue(), authentication, expirySeconds);
	}

	@Override
	public OAuth2RefreshToken readRefreshToken(String tokenValue) {
		return this.refreshTokenStore.get(tokenValue);
	}

	@Override
	public void removeRefreshToken(OAuth2RefreshToken refreshToken) {
		removeRefreshToken(refreshToken.getValue());
	}

	@Override
	public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
		removeAccessTokenUsingRefreshToken(refreshToken.getValue());
	}

	@Override
	public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName) {
		IMap<String, OAuth2AccessToken> map = map(getApprovalKey(clientId, userName));
		return map.values();
	}

	@Override
	public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
		IMap<String, OAuth2AccessToken> map = map(clientId);
		return map.values();
	}

	private void removeAccessTokenUsingRefreshToken(String refreshToken) {
		String accessToken = this.refreshTokenToAccessTokenStore.remove(refreshToken);
		if (accessToken != null) {
			removeAccessToken(accessToken);
		}
	}

	private void removeRefreshToken(String tokenValue) {
		this.refreshTokenStore.remove(tokenValue);
		this.refreshTokenAuthenticationStore.remove(tokenValue);
		this.refreshTokenToAccessTokenStore.remove(tokenValue);
	}

	private void removeAccessToken(String tokenValue) {
		OAuth2AccessToken removed = this.accessTokenStore.remove(tokenValue);
		this.accessTokenToRefreshTokenStore.remove(tokenValue);
		// Don't remove the refresh token - it's up to the caller to do that
		OAuth2Authentication authentication = this.authenticationStore.remove(tokenValue);
		if (authentication != null) {
			this.authenticationToAccessTokenStore.remove(authenticationKeyGenerator.extractKey(authentication));

			String clientId = authentication.getOAuth2Request().getClientId();
			String clientIdAndUsername = getApprovalKey(clientId, authentication.getName());

			IMap<String, OAuth2AccessToken> byClientId = map(clientId);
			IMap<String, OAuth2AccessToken> byClientIdAndUsername = map(clientIdAndUsername);

			byClientId.remove(removed.getValue());
			byClientIdAndUsername.remove(removed.getValue());

			this.authenticationToAccessTokenStore.remove(authenticationKeyGenerator.extractKey(authentication));
		}
	}

	private OAuth2Authentication readAuthenticationForRefreshToken(String token) {
		return this.refreshTokenAuthenticationStore.get(token);
	}

	private String getApprovalKey(OAuth2Authentication authentication) {
		String userName = authentication.getUserAuthentication() == null ? "" : authentication.getUserAuthentication().getName();
		return getApprovalKey(authentication.getOAuth2Request().getClientId(), userName);
	}

	private String getApprovalKey(String clientId, String userName) {
		return clientId + (userName == null ? "" : ":" + userName);
	}

	private <K, V> IMap<K, V> map(String id) {
		return hazelcastInstance.getMap(id);
	}

	private <K, V> void putRespectExpirationSeconds(IMap<K, V> map, K k, V v, @Nullable Integer expiry) {
		if (expiry != null) map.put(k, v, expiry, TimeUnit.SECONDS);
		else map.put(k, v);
	}

}
