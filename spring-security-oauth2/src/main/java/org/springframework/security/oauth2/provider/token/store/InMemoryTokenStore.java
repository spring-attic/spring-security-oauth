package org.springframework.security.oauth2.provider.token.store;

import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.DelayQueue;
import java.util.concurrent.Delayed;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.util.Assert;

/**
 * Implementation of token services that stores tokens in memory.
 * 
 * @author Ryan Heaton
 * @author Luke Taylor
 * @author Dave Syer
 */
public class InMemoryTokenStore implements TokenStore {

	private static final int DEFAULT_FLUSH_INTERVAL = 1000;

	private final ConcurrentHashMap<String, OAuth2AccessToken> accessTokenStore = new ConcurrentHashMap<String, OAuth2AccessToken>();

	private final ConcurrentHashMap<String, OAuth2AccessToken> authenticationToAccessTokenStore = new ConcurrentHashMap<String, OAuth2AccessToken>();

	private final ConcurrentHashMap<String, Collection<OAuth2AccessToken>> userNameToAccessTokenStore = new ConcurrentHashMap<String, Collection<OAuth2AccessToken>>();

	private final ConcurrentHashMap<String, Collection<OAuth2AccessToken>> clientIdToAccessTokenStore = new ConcurrentHashMap<String, Collection<OAuth2AccessToken>>();

	private final ConcurrentHashMap<String, OAuth2RefreshToken> refreshTokenStore = new ConcurrentHashMap<String, OAuth2RefreshToken>();

	private final ConcurrentHashMap<String, String> accessTokenToRefreshTokenStore = new ConcurrentHashMap<String, String>();

	private final ConcurrentHashMap<String, OAuth2Authentication> authenticationStore = new ConcurrentHashMap<String, OAuth2Authentication>();

	private final ConcurrentHashMap<String, OAuth2Authentication> refreshTokenAuthenticationStore = new ConcurrentHashMap<String, OAuth2Authentication>();

	private final ConcurrentHashMap<String, String> refreshTokenToAccessTokenStore = new ConcurrentHashMap<String, String>();

	private final DelayQueue<TokenExpiry> expiryQueue = new DelayQueue<TokenExpiry>();

	private final ConcurrentHashMap<String, TokenExpiry> expiryMap = new ConcurrentHashMap<String, TokenExpiry>();

	private int flushInterval = DEFAULT_FLUSH_INTERVAL;

	private AuthenticationKeyGenerator authenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();

	private AtomicInteger flushCounter = new AtomicInteger(0);

	/**
	 * The number of tokens to store before flushing expired tokens. Defaults to 1000.
	 * 
	 * @param flushInterval the interval to set
	 */
	public void setFlushInterval(int flushInterval) {
		this.flushInterval = flushInterval;
	}

	/**
	 * The interval (count of token inserts) between flushing expired tokens.
	 * 
	 * @return the flushInterval the flush interval
	 */
	public int getFlushInterval() {
		return flushInterval;
	}

	/**
	 * Convenience method for super admin users to remove all tokens (useful for testing, not really in production)
	 */
	public void clear() {
		accessTokenStore.clear();
		authenticationToAccessTokenStore.clear();
		clientIdToAccessTokenStore.clear();
		refreshTokenStore.clear();
		accessTokenToRefreshTokenStore.clear();
		authenticationStore.clear();
		refreshTokenAuthenticationStore.clear();
		refreshTokenToAccessTokenStore.clear();
		expiryQueue.clear();
	}

	public void setAuthenticationKeyGenerator(AuthenticationKeyGenerator authenticationKeyGenerator) {
		this.authenticationKeyGenerator = authenticationKeyGenerator;
	}

	public int getAccessTokenCount() {
		Assert.state(accessTokenStore.isEmpty() || accessTokenStore.size() >= accessTokenToRefreshTokenStore.size(),
				"Too many refresh tokens");
		Assert.state(accessTokenStore.size() == authenticationToAccessTokenStore.size(),
				"Inconsistent token store state");
		Assert.state(accessTokenStore.size() <= authenticationStore.size(), "Inconsistent authentication store state");
		return accessTokenStore.size();
	}

	public int getRefreshTokenCount() {
		Assert.state(refreshTokenStore.size() == refreshTokenToAccessTokenStore.size(),
				"Inconsistent refresh token store state");
		return accessTokenStore.size();
	}

	public int getExpiryTokenCount() {
		return expiryQueue.size();
	}

	public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
		String key = authenticationKeyGenerator.extractKey(authentication);
		OAuth2AccessToken accessToken = authenticationToAccessTokenStore.get(key);
		if (accessToken != null
				&& !key.equals(authenticationKeyGenerator.extractKey(readAuthentication(accessToken.getValue())))) {
			// Keep the stores consistent (maybe the same user is represented by this authentication but the details
			// have changed)
			storeAccessToken(accessToken, authentication);
		}
		return accessToken;
	}

	public OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
		return readAuthentication(token.getValue());
	}

	public OAuth2Authentication readAuthentication(String token) {
		return this.authenticationStore.get(token);
	}

	public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken token) {
		return readAuthenticationForRefreshToken(token.getValue());
	}

	public OAuth2Authentication readAuthenticationForRefreshToken(String token) {
		return this.refreshTokenAuthenticationStore.get(token);
	}

	public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
		if (this.flushCounter.incrementAndGet() >= this.flushInterval) {
			flush();
			this.flushCounter.set(0);
		}
		this.accessTokenStore.put(token.getValue(), token);
		this.authenticationStore.put(token.getValue(), authentication);
		this.authenticationToAccessTokenStore.put(authenticationKeyGenerator.extractKey(authentication), token);
		if (!authentication.isClientOnly()) {
			addToCollection(this.userNameToAccessTokenStore, getApprovalKey(authentication), token);
		}
		addToCollection(this.clientIdToAccessTokenStore, authentication.getOAuth2Request().getClientId(), token);
		if (token.getExpiration() != null) {
			TokenExpiry expiry = new TokenExpiry(token.getValue(), token.getExpiration());
			// Remove existing expiry for this token if present
			expiryQueue.remove(expiryMap.put(token.getValue(), expiry));
			this.expiryQueue.put(expiry);
		}
		if (token.getRefreshToken() != null && token.getRefreshToken().getValue() != null) {
			this.refreshTokenToAccessTokenStore.put(token.getRefreshToken().getValue(), token.getValue());
			this.accessTokenToRefreshTokenStore.put(token.getValue(), token.getRefreshToken().getValue());
		}
	}

	private String getApprovalKey(OAuth2Authentication authentication) {
		String userName = authentication.getUserAuthentication() == null ? "" : authentication.getUserAuthentication()
				.getName();
		return getApprovalKey(authentication.getOAuth2Request().getClientId(), userName);
	}

	private String getApprovalKey(String clientId, String userName) {
		return clientId + (userName==null ? "" : ":" + userName);
	}

	private void addToCollection(ConcurrentHashMap<String, Collection<OAuth2AccessToken>> store, String key,
			OAuth2AccessToken token) {
		if (!store.containsKey(key)) {
			synchronized (store) {
				if (!store.containsKey(key)) {
					store.put(key, new HashSet<OAuth2AccessToken>());
				}
			}
		}
		store.get(key).add(token);
	}

	public void removeAccessToken(OAuth2AccessToken accessToken) {
		removeAccessToken(accessToken.getValue());
	}

	public OAuth2AccessToken readAccessToken(String tokenValue) {
		return this.accessTokenStore.get(tokenValue);
	}

	public void removeAccessToken(String tokenValue) {
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

	public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
		this.refreshTokenStore.put(refreshToken.getValue(), refreshToken);
		this.refreshTokenAuthenticationStore.put(refreshToken.getValue(), authentication);
	}

	public OAuth2RefreshToken readRefreshToken(String tokenValue) {
		return this.refreshTokenStore.get(tokenValue);
	}

	public void removeRefreshToken(OAuth2RefreshToken refreshToken) {
		removeRefreshToken(refreshToken.getValue());
	}

	public void removeRefreshToken(String tokenValue) {
		this.refreshTokenStore.remove(tokenValue);
		this.refreshTokenAuthenticationStore.remove(tokenValue);
		this.refreshTokenToAccessTokenStore.remove(tokenValue);
	}

	public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
		removeAccessTokenUsingRefreshToken(refreshToken.getValue());
	}

	private void removeAccessTokenUsingRefreshToken(String refreshToken) {
		String accessToken = this.refreshTokenToAccessTokenStore.remove(refreshToken);
		if (accessToken != null) {
			removeAccessToken(accessToken);
		}
	}

	public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName) {
		Collection<OAuth2AccessToken> result = userNameToAccessTokenStore.get(getApprovalKey(clientId, userName));
		return result != null ? Collections.<OAuth2AccessToken> unmodifiableCollection(result) : Collections
				.<OAuth2AccessToken> emptySet();
	}

	public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
		Collection<OAuth2AccessToken> result = clientIdToAccessTokenStore.get(clientId);
		return result != null ? Collections.<OAuth2AccessToken> unmodifiableCollection(result) : Collections
				.<OAuth2AccessToken> emptySet();
	}

	private void flush() {
		TokenExpiry expiry = expiryQueue.poll();
		while (expiry != null) {
			removeAccessToken(expiry.getValue());
			expiry = expiryQueue.poll();
		}
	}

	private static class TokenExpiry implements Delayed {

		private final long expiry;

		private final String value;

		public TokenExpiry(String value, Date date) {
			this.value = value;
			this.expiry = date.getTime();
		}

		public int compareTo(Delayed other) {
			if (this == other) {
				return 0;
			}
			long diff = getDelay(TimeUnit.MILLISECONDS) - other.getDelay(TimeUnit.MILLISECONDS);
			return (diff == 0 ? 0 : ((diff < 0) ? -1 : 1));
		}

		public long getDelay(TimeUnit unit) {
			return expiry - System.currentTimeMillis();
		}

		public String getValue() {
			return value;
		}

	}

}
