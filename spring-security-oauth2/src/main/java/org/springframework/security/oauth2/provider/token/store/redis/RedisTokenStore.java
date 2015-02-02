package org.springframework.security.oauth2.provider.token.store.redis;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.TokenStore;

public class RedisTokenStore implements TokenStore {

	private static final String ACCESS = "access:";
	private static final String AUTH_TO_ACCESS = "auth_to_access:";
	private static final String AUTH = "auth:";
	private static final String REFRESH_AUTH = "refresh_auth:";
	private static final String ACCESS_TO_REFRESH = "access_to_refresh:";
	private static final String REFRESH = "refresh:";
	private static final String REFRESH_TO_ACCESS = "refresh_to_access:";
	private static final String CLIENT_ID_TO_ACCESS = "client_id_to_access:";
	private static final String UNAME_TO_ACCESS = "uname_to_access:";

	private final RedisConnectionFactory connectionFactory;
	private AuthenticationKeyGenerator authenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();
	private RedisTokenStoreSerializationStrategy serializationStrategy = new JdkSerializationStrategy();

	public RedisTokenStore(RedisConnectionFactory connectionFactory) {
		this.connectionFactory = connectionFactory;
	}

	public void setAuthenticationKeyGenerator(AuthenticationKeyGenerator authenticationKeyGenerator) {
		this.authenticationKeyGenerator = authenticationKeyGenerator;
	}

	public void setSerializationStrategy(RedisTokenStoreSerializationStrategy serializationStrategy) {
		this.serializationStrategy = serializationStrategy;
	}

	private RedisConnection getConnection() {
		return connectionFactory.getConnection();
	}

	private byte[] serialize(Object object) {
		return serializationStrategy.serialize(object);
	}

	private OAuth2AccessToken deserializeAccessToken(byte[] bytes) {
		return serializationStrategy.deserialize(bytes, OAuth2AccessToken.class);
	}

	private OAuth2Authentication deserializeAuthentication(byte[] bytes) {
		return serializationStrategy.deserialize(bytes, OAuth2Authentication.class);
	}

	private OAuth2RefreshToken deserializeRefreshToken(byte[] bytes) {
		return serializationStrategy.deserialize(bytes, OAuth2RefreshToken.class);
	}

	private byte[] serialize(String string) {
		return serializationStrategy.serialize(string);
	}

	private String deserializeString(byte[] bytes) {
		return serializationStrategy.deserializeString(bytes);
	}

	@Override
	public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
		String key = authenticationKeyGenerator.extractKey(authentication);
		byte[] keyBytes = serialize(AUTH_TO_ACCESS + key);
		byte[] bytes = null;
		RedisConnection conn = getConnection();
		try {
			bytes = conn.get(keyBytes);
		} finally {
			conn.close();
		}
		OAuth2AccessToken accessToken = deserializeAccessToken(bytes);
		if (accessToken != null
				&& !key.equals(authenticationKeyGenerator.extractKey(readAuthentication(accessToken.getValue())))) {
			// Keep the stores consistent (maybe the same user is
			// represented by this authentication but the details have
			// changed)
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
		byte[] bytes = null;
		RedisConnection conn = getConnection();
		try {
			bytes = conn.get(serialize(AUTH + token));
		} finally {
			conn.close();
		}
		OAuth2Authentication auth = deserializeAuthentication(bytes);
		return auth;
	}

	@Override
	public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken token) {
		return readAuthenticationForRefreshToken(token.getValue());
	}

	public OAuth2Authentication readAuthenticationForRefreshToken(String token) {
		byte[] bytes = null;
		RedisConnection conn = getConnection();
		try {
			bytes = conn.get(serialize(REFRESH_AUTH + token));
		} finally {
			conn.close();
		}
		OAuth2Authentication auth = deserializeAuthentication(bytes);
		return auth;
	}

	@Override
	public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
		byte[] serializedAccessToken = serialize(token);
		byte[] serializedAuth = serialize(authentication);
		byte[] accessKey = serialize(ACCESS + token.getValue());
		byte[] authKey = serialize(AUTH + token.getValue());
		byte[] authToAccessKey = serialize(AUTH_TO_ACCESS + authenticationKeyGenerator.extractKey(authentication));
		byte[] approvalKey = serialize(UNAME_TO_ACCESS + getApprovalKey(authentication));
		byte[] clientId = serialize(CLIENT_ID_TO_ACCESS + authentication.getOAuth2Request().getClientId());
		OAuth2RefreshToken refreshToken = token.getRefreshToken();

		RedisConnection conn = getConnection();
		try {
			conn.openPipeline();
			conn.set(accessKey, serializedAccessToken);
			conn.set(authKey, serializedAuth);
			conn.set(authToAccessKey, serializedAccessToken);
			if (!authentication.isClientOnly()) {
				conn.rPush(approvalKey, serializedAccessToken);
			}
			conn.rPush(clientId, serializedAccessToken);
			if (token.getExpiration() != null) {
				int seconds = token.getExpiresIn();
				conn.expire(accessKey, seconds);
				conn.expire(authKey, seconds);
				conn.expire(authToAccessKey, seconds);
				conn.expire(clientId, seconds);
				conn.expire(approvalKey, seconds);
			}
			if (refreshToken != null && refreshToken.getValue() != null) {
				byte[] refresh = serialize(refreshToken.getValue());
				byte[] auth = serialize(token.getValue());
				byte[] refreshToAccessKey = serialize(REFRESH_TO_ACCESS + refreshToken.getValue());
				conn.set(refreshToAccessKey, auth);
				byte[] accessToRefreshKey = serialize(ACCESS_TO_REFRESH + token.getValue());
				conn.set(accessToRefreshKey, refresh);
				if (refreshToken instanceof ExpiringOAuth2RefreshToken) {
					ExpiringOAuth2RefreshToken expiringRefreshToken = (ExpiringOAuth2RefreshToken) refreshToken;
					Date expiration = expiringRefreshToken.getExpiration();
					if (expiration != null) {
						int seconds = (int) (expiration.getTime() / 1000);
						conn.expireAt(refreshToAccessKey, seconds);
						conn.expireAt(accessToRefreshKey, seconds);
					}
				}
			}
			conn.closePipeline();
		} finally {
			conn.close();
		}
	}

	private static String getApprovalKey(OAuth2Authentication authentication) {
		String userName = authentication.getUserAuthentication() == null ? "" : authentication.getUserAuthentication()
				.getName();
		return getApprovalKey(authentication.getOAuth2Request().getClientId(), userName);
	}

	private static String getApprovalKey(String clientId, String userName) {
		return clientId + (userName == null ? "" : ":" + userName);
	}

	@Override
	public void removeAccessToken(OAuth2AccessToken accessToken) {
		removeAccessToken(accessToken.getValue());
	}

	@Override
	public OAuth2AccessToken readAccessToken(String tokenValue) {
		byte[] keyBytes = serialize(ACCESS + tokenValue);
		byte[] bytes = null;
		RedisConnection conn = getConnection();
		try {
			bytes = conn.get(keyBytes);
		} finally {
			conn.close();
		}
		OAuth2AccessToken accessToken = deserializeAccessToken(bytes);
		return accessToken;
	}

	public void removeAccessToken(String tokenValue) {
		byte[] accessKey = serialize(ACCESS + tokenValue);
		byte[] authKey = serialize(AUTH + tokenValue);
		byte[] accessToRefreshKey = serialize(ACCESS_TO_REFRESH + tokenValue);
		RedisConnection conn = getConnection();
		try {
			conn.openPipeline();
			conn.get(accessKey);
			conn.get(authKey);
			List<Object> results = conn.closePipeline();
			byte[] accessBytes = (byte[]) results.get(0);
			byte[] authBytes = (byte[]) results.get(1);
			OAuth2Authentication authentication = deserializeAuthentication(authBytes);

			conn.openPipeline();
			conn.del(accessKey);
			conn.del(accessToRefreshKey);
			// Don't remove the refresh token - it's up to the caller to do that
			conn.del(serialize(AUTH + tokenValue));
			if (authentication != null) {
				String auth = authenticationKeyGenerator.extractKey(authentication);
				conn.del(serialize(AUTH_TO_ACCESS + auth));
				byte[] unameKey = serialize(UNAME_TO_ACCESS + authentication.getName());
				conn.lRem(unameKey, 1, accessBytes);
				byte[] clientId = serialize(CLIENT_ID_TO_ACCESS + authentication.getOAuth2Request().getClientId());
				conn.lRem(clientId, 1, accessBytes);
				conn.del(serialize(ACCESS + authKey));
			}
			conn.closePipeline();
		} finally {
			conn.close();
		}
	}

	@Override
	public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
		byte[] refreshKey = serialize(REFRESH + refreshToken.getValue());
		byte[] refreshAuthKey = serialize(REFRESH_AUTH + refreshToken.getValue());
		Date expiration = null;
		if (refreshToken instanceof ExpiringOAuth2RefreshToken) {
			ExpiringOAuth2RefreshToken expiringRefreshToken = (ExpiringOAuth2RefreshToken) refreshToken;
			expiration = expiringRefreshToken.getExpiration();
		}

		RedisConnection conn = getConnection();
		try {
			conn.openPipeline();
			conn.set(refreshKey, serialize(refreshToken));
			conn.set(refreshAuthKey, serialize(authentication));
			if (expiration != null) {
				int seconds = (int) (expiration.getTime() / 1000);
				conn.expireAt(refreshKey, seconds);
				conn.expireAt(refreshAuthKey, seconds);
			}
			conn.closePipeline();
		} finally {
			conn.close();
		}
	}

	@Override
	public OAuth2RefreshToken readRefreshToken(String tokenValue) {
		RedisConnection conn = getConnection();
		byte[] bytes = null;
		try {
			bytes = conn.get(serialize(REFRESH + tokenValue));
		} finally {
			conn.close();
		}
		OAuth2RefreshToken refreshToken = deserializeRefreshToken(bytes);
		return refreshToken;
	}

	@Override
	public void removeRefreshToken(OAuth2RefreshToken refreshToken) {
		removeRefreshToken(refreshToken.getValue());
	}

	public void removeRefreshToken(String tokenValue) {
		RedisConnection conn = getConnection();
		try {
			conn.openPipeline();
			conn.del(serialize(REFRESH + tokenValue));
			conn.del(serialize(REFRESH_TO_ACCESS + tokenValue));
			conn.del(serialize(ACCESS_TO_REFRESH + tokenValue));
			conn.closePipeline();
		} finally {
			conn.close();
		}
	}

	@Override
	public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
		removeAccessTokenUsingRefreshToken(refreshToken.getValue());
	}

	private void removeAccessTokenUsingRefreshToken(String refreshToken) {
		byte[] refreshToAccess = serialize(REFRESH_TO_ACCESS + refreshToken);
		byte[] bytes = null;
		RedisConnection conn = getConnection();
		try {
			conn.openPipeline();
			conn.get(refreshToAccess);
			conn.del(refreshToAccess);
			List<Object> results = conn.closePipeline();
			bytes = (byte[]) results.get(0);
		} finally {
			conn.close();
		}
		String accessToken = deserializeString(bytes);
		if (accessToken != null) {
			removeAccessToken(accessToken);
		}
	}

	@Override
	public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName) {
		List<byte[]> byteList = null;
		RedisConnection conn = getConnection();
		try {
			byte[] approvalKey = serialize(UNAME_TO_ACCESS + getApprovalKey(clientId, userName));
			byteList = conn.lRange(approvalKey, 0, -1);
		} finally {
			conn.close();
		}
		if (byteList == null || byteList.size() == 0) {
			return Collections.<OAuth2AccessToken> emptySet();
		}
		List<OAuth2AccessToken> accessTokens = new ArrayList<OAuth2AccessToken>(byteList.size());
		for (byte[] bytes : byteList) {
			OAuth2AccessToken accessToken = deserializeAccessToken(bytes);
			accessTokens.add(accessToken);
		}
		return Collections.<OAuth2AccessToken> unmodifiableCollection(accessTokens);
	}

	@Override
	public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
		byte[] key = serialize(CLIENT_ID_TO_ACCESS + clientId);
		List<byte[]> byteList = null;
		RedisConnection conn = getConnection();
		try {
			byteList = conn.lRange(key, 0, -1);
		} finally {
			conn.close();
		}
		if (byteList == null || byteList.size() == 0) {
			return Collections.<OAuth2AccessToken> emptySet();
		}
		List<OAuth2AccessToken> accessTokens = new ArrayList<OAuth2AccessToken>(byteList.size());
		for (byte[] bytes : byteList) {
			OAuth2AccessToken accessToken = deserializeAccessToken(bytes);
			accessTokens.add(accessToken);
		}
		return Collections.<OAuth2AccessToken> unmodifiableCollection(accessTokens);
	}
}
