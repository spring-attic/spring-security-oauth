package org.springframework.security.oauth2.provider.token;

import java.util.concurrent.ConcurrentHashMap;

import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.util.Assert;

/**
 * Implementation of token services that stores tokens in memory.
 * 
 * @author Ryan Heaton
 * @author Luke Taylor
 * @author Dave Syer
 */
public class InMemoryTokenStore implements TokenStore {

	private final ConcurrentHashMap<String, OAuth2AccessToken> accessTokenStore = new ConcurrentHashMap<String, OAuth2AccessToken>();

	private final ConcurrentHashMap<String, OAuth2AccessToken> authenticationToAccessTokenStore = new ConcurrentHashMap<String, OAuth2AccessToken>();

	private final ConcurrentHashMap<String, ExpiringOAuth2RefreshToken> refreshTokenStore = new ConcurrentHashMap<String, ExpiringOAuth2RefreshToken>();

	private final ConcurrentHashMap<String, String> accessTokenToRefreshTokenStore = new ConcurrentHashMap<String, String>();

	private final ConcurrentHashMap<String, OAuth2Authentication> authenticationStore = new ConcurrentHashMap<String, OAuth2Authentication>();

	private final ConcurrentHashMap<String, String> refreshTokenToAcessTokenStore = new ConcurrentHashMap<String, String>();

	private AuthenticationKeyGenerator authenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();
	
	public void setAuthenticationKeyGenerator(AuthenticationKeyGenerator authenticationKeyGenerator) {
		this.authenticationKeyGenerator  = authenticationKeyGenerator;
	}

	public int getAccessTokenCount() {
		Assert.state(accessTokenStore.size()>=accessTokenToRefreshTokenStore.size(), "Too many refresh tokens");
		Assert.state(accessTokenStore.size()==authenticationToAccessTokenStore.size(), "Inconsistent token store state");
		Assert.state(accessTokenStore.size()<=authenticationStore.size(), "Inconsistent authentication store state");
		return accessTokenStore.size();
	}
	
	public int getRefreshTokenCount() {
		Assert.state(refreshTokenStore.size()==refreshTokenToAcessTokenStore.size(), "Inconsistent refresh token store state");
		return accessTokenStore.size();
	}
	
	public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
		return authenticationToAccessTokenStore.get(authenticationKeyGenerator.extractKey(authentication));
	}

	public OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
		return this.authenticationStore.get(token.getValue());
	}

	public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
		this.accessTokenStore.put(token.getValue(), token);
		this.authenticationStore.put(token.getValue(), authentication);
		this.authenticationToAccessTokenStore.put(authenticationKeyGenerator.extractKey(authentication), token);
		if (token.getRefreshToken() != null && token.getRefreshToken().getValue() != null) {
			this.refreshTokenToAcessTokenStore.put(token.getRefreshToken().getValue(), token.getValue());
			this.accessTokenToRefreshTokenStore.put(token.getValue(), token.getRefreshToken().getValue());
		}
	}

	public OAuth2AccessToken readAccessToken(String tokenValue) {
		return this.accessTokenStore.get(tokenValue);
	}

	public void removeAccessToken(String tokenValue) {
		this.accessTokenStore.remove(tokenValue);
		String refresh = this.accessTokenToRefreshTokenStore.remove(tokenValue);
		if (refresh!=null) {
			this.refreshTokenStore.remove(tokenValue);
			this.refreshTokenToAcessTokenStore.remove(tokenValue);
		}
		OAuth2Authentication authentication = this.authenticationStore.remove(tokenValue);
		if (authentication!=null) {
			this.authenticationToAccessTokenStore.remove(authenticationKeyGenerator.extractKey(authentication));
		}
	}

	public OAuth2Authentication readAuthentication(ExpiringOAuth2RefreshToken token) {
		return this.authenticationStore.get(token.getValue());
	}

	public void storeRefreshToken(ExpiringOAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
		this.refreshTokenStore.put(refreshToken.getValue(), refreshToken);
		this.authenticationStore.put(refreshToken.getValue(), authentication);
	}

	public ExpiringOAuth2RefreshToken readRefreshToken(String tokenValue) {
		return this.refreshTokenStore.get(tokenValue);
	}

	public void removeRefreshToken(String tokenValue) {
		this.refreshTokenStore.remove(tokenValue);
		this.authenticationStore.remove(tokenValue);
	}

	public void removeAccessTokenUsingRefreshToken(String refreshToken) {
		String accessToken = this.refreshTokenToAcessTokenStore.remove(refreshToken);
		if (accessToken != null) {
			this.accessTokenStore.remove(accessToken);
			this.authenticationStore.remove(accessToken);
		}
	}
}
