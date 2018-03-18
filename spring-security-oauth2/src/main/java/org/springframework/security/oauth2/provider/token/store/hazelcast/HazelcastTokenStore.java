package org.springframework.security.oauth2.provider.token.store.hazelcast;

import com.hazelcast.client.HazelcastClient;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.IMap;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.TokenStore;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;

/**
 * Implementation of token services that stores tokens in memory.
 *
 * @author Ryan Heaton
 * @author Luke Taylor
 * @author Dave Syer
 */
public class HazelcastTokenStore implements TokenStore {

	private IMap<String, OAuth2AccessToken> accessTokenStore;
	private IMap<String, OAuth2AccessToken> authenticationToAccessTokenStore;
	private IMap<String, Collection<OAuth2AccessToken>> userNameToAccessTokenStore;
	private IMap<String, Collection<OAuth2AccessToken>> clientIdToAccessTokenStore;
	private IMap<String, OAuth2RefreshToken> refreshTokenStore;
	private IMap<String, String> accessTokenToRefreshTokenStore;
	private IMap<String, OAuth2Authentication> authenticationStore;
	private IMap<String, OAuth2Authentication> refreshTokenAuthenticationStore;
	private IMap<String, String> refreshTokenToAccessTokenStore;

	private AuthenticationKeyGenerator authenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();

	public HazelcastTokenStore(String instanceName) {
		initMaps(HazelcastClient.getHazelcastClientByName(instanceName));
	}

	public HazelcastTokenStore(HazelcastInstance instance) {
		initMaps(instance);
	}

	private void initMaps(HazelcastInstance hazelcastInstance) {
		accessTokenStore = hazelcastInstance.getMap("accessTokenStore");
		authenticationToAccessTokenStore = hazelcastInstance.getMap("authenticationToAccessTokenStore");
		userNameToAccessTokenStore = hazelcastInstance.getMap("userNameToAccessTokenStore");
		clientIdToAccessTokenStore = hazelcastInstance.getMap("clientIdToAccessTokenStore");
		refreshTokenStore = hazelcastInstance.getMap("refreshTokenStore");
		accessTokenToRefreshTokenStore = hazelcastInstance.getMap("accessTokenToRefreshTokenStore");
		authenticationStore = hazelcastInstance.getMap("authenticationStore");
		refreshTokenAuthenticationStore = hazelcastInstance.getMap("refreshTokenAuthenticationStore");
		refreshTokenToAccessTokenStore = hazelcastInstance.getMap("refreshTokenToAccessTokenStore");
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

		this.accessTokenStore.put(token.getValue(), token);
		this.authenticationStore.put(token.getValue(), authentication);
		this.authenticationToAccessTokenStore.put(authenticationKeyGenerator.extractKey(authentication), token);
		if (!authentication.isClientOnly()) {

			getOrDefault(
					this.userNameToAccessTokenStore,
					getApprovalKey(authentication),
					new HashSet<OAuth2AccessToken>()
			).add(token);

		}

		getOrDefault(
				this.clientIdToAccessTokenStore,
				authentication.getOAuth2Request().getClientId(),
				new HashSet<OAuth2AccessToken>()
		).add(token);

		if (token.getRefreshToken() != null && token.getRefreshToken().getValue() != null) {
			this.refreshTokenToAccessTokenStore.put(token.getRefreshToken().getValue(), token.getValue());
			this.accessTokenToRefreshTokenStore.put(token.getValue(), token.getRefreshToken().getValue());
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
	public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
		this.refreshTokenStore.put(refreshToken.getValue(), refreshToken);
		this.refreshTokenAuthenticationStore.put(refreshToken.getValue(), authentication);
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
		Collection<OAuth2AccessToken> result = userNameToAccessTokenStore.get(getApprovalKey(clientId, userName));
		return result != null ? Collections.unmodifiableCollection(result) : Collections.<OAuth2AccessToken>emptySet();
	}

	@Override
	public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
		Collection<OAuth2AccessToken> result = clientIdToAccessTokenStore.get(clientId);
		return result != null ? Collections.unmodifiableCollection(result) : Collections.<OAuth2AccessToken>emptySet();
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
			Collection<OAuth2AccessToken> tokens;
			String clientId = authentication.getOAuth2Request().getClientId();
			tokens = this.userNameToAccessTokenStore.get(getApprovalKey(clientId, authentication.getName()));
			if (tokens != null) {
				tokens.remove(removed);
			}
			tokens = this.clientIdToAccessTokenStore.get(clientId);
			if (tokens != null) {
				tokens.remove(removed);
			}
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

	private <K, V> V getOrDefault(Map<K, V> map, K key, V defaultValue) {
		V v;
		return ((v = map.get(key)) != null) ? v : defaultValue;
	}

}
