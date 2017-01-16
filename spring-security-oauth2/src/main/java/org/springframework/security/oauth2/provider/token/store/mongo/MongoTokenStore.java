/*
 * Copyright 2008 Web Cohesion
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.provider.token.store.mongo;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.util.SerializationUtils;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.util.Assert;

/**
 * Store tokens in the MongoDB.
 *
 * @author Marcos Barbero
 */
public class MongoTokenStore implements TokenStore {

	private static final String AUTHENTICATION_ID = "authenticationId";
	private static final String CLIENT_ID = "clientId";
	private static final String TOKEN_ID = "tokenId";
	private static final String USER_NAME = "userName";

	private final MongoTemplate mongoTemplate;

	private AuthenticationKeyGenerator authenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();

	public MongoTokenStore(final MongoTemplate mongoTemplate) {
		Assert.notNull(mongoTemplate, "MongoTemplate cannot be null.");
		this.mongoTemplate = mongoTemplate;
	}

	public MongoTokenStore(final MongoTemplate mongoTemplate,
			final AuthenticationKeyGenerator authenticationKeyGenerator) {
		Assert.notNull(mongoTemplate, "MongoTemplate cannot be null.");
		Assert.notNull(authenticationKeyGenerator,
				"AuthenticationKeyGenerator cannot be null.");
		this.mongoTemplate = mongoTemplate;
		this.authenticationKeyGenerator = authenticationKeyGenerator;
	}

	public void setAuthenticationKeyGenerator(
			AuthenticationKeyGenerator authenticationKeyGenerator) {
		this.authenticationKeyGenerator = authenticationKeyGenerator;
	}

	@Override
	public OAuth2Authentication readAuthentication(final OAuth2AccessToken token) {
		return readAuthentication(token.getValue());
	}

	@Override
	public OAuth2Authentication readAuthentication(final String token) {
		OAuth2Authentication authentication = null;
		final String tokenId = extractTokenKey(token);

		MongoOAuthAccessToken mongoOAuthAccessToken = this.mongoTemplate
				.findOne(findByTokenId(tokenId), MongoOAuthAccessToken.class);

		if (mongoOAuthAccessToken != null) {
			try {
				authentication = deserializeAuthentication(
						mongoOAuthAccessToken.getAuthentication());
			}
			catch (IllegalArgumentException e) {
				removeAccessToken(token);
			}
		}

		return authentication;
	}

	@Override
	public void storeAccessToken(final OAuth2AccessToken token,
			final OAuth2Authentication authentication) {
		String refreshToken = null;
		if (token.getRefreshToken() != null) {
			refreshToken = token.getRefreshToken().getValue();
		}

		if (readAccessToken(token.getValue()) != null) {
			removeAccessToken(token.getValue());
		}

		final String tokenKey = extractTokenKey(token.getValue());

		final MongoOAuthAccessToken accessToken = new MongoOAuthAccessToken(tokenKey,
				serializeAccessToken(token),
				this.authenticationKeyGenerator.extractKey(authentication),
				authentication.isClientOnly() ? null : authentication.getName(),
				authentication.getOAuth2Request().getClientId(),
				serializeAuthentication(authentication), extractTokenKey(refreshToken));

		this.mongoTemplate.insert(accessToken);
	}

	public void removeAccessToken(final String tokenValue) {
		final String tokenKey = extractTokenKey(tokenValue);
		this.mongoTemplate.remove(findByTokenId(tokenKey), MongoOAuthAccessToken.class);
	}

	@Override
	public OAuth2AccessToken readAccessToken(final String tokenValue) {
		final String tokenKey = extractTokenKey(tokenValue);
		final MongoOAuthAccessToken accessToken = this.mongoTemplate
				.findOne(findByTokenId(tokenKey), MongoOAuthAccessToken.class);
		if (accessToken != null) {
			try {
				return deserializeAccessToken(accessToken.getToken());
			}
			catch (IllegalArgumentException e) {
				removeAccessToken(tokenValue);
			}
		}
		return null;
	}

	@Override
	public void removeAccessToken(final OAuth2AccessToken token) {
		removeAccessToken(token.getValue());
	}

	@Override
	public void storeRefreshToken(final OAuth2RefreshToken refreshToken,
			final OAuth2Authentication oAuth2Authentication) {
		final String tokenKey = extractTokenKey(refreshToken.getValue());
		final byte[] token = serializeRefreshToken(refreshToken);
		final byte[] authentication = serializeAuthentication(oAuth2Authentication);

		final MongoOAuthRefreshToken mongoRefreshToken = new MongoOAuthRefreshToken(
				tokenKey, token, authentication);

		this.mongoTemplate.insert(mongoRefreshToken);
	}

	@Override
	public OAuth2RefreshToken readRefreshToken(final String tokenValue) {
		OAuth2RefreshToken refreshToken = null;
		final String tokenKey = extractTokenKey(tokenValue);
		final MongoOAuthRefreshToken mongoOAuth2RefreshToken = this.mongoTemplate
				.findOne(findByTokenId(tokenKey), MongoOAuthRefreshToken.class);

		if (mongoOAuth2RefreshToken != null) {
			try {
				refreshToken = deserializeRefreshToken(
						mongoOAuth2RefreshToken.getToken());
			}
			catch (IllegalArgumentException e) {
				removeRefreshToken(tokenValue);
			}
		}
		return refreshToken;
	}

	@Override
	public OAuth2Authentication readAuthenticationForRefreshToken(
			final OAuth2RefreshToken token) {
		return readAuthenticationForRefreshToken(token.getValue());
	}

	@Override
	public void removeRefreshToken(final OAuth2RefreshToken token) {
		removeRefreshToken(token.getValue());
	}

	@Override
	public void removeAccessTokenUsingRefreshToken(
			final OAuth2RefreshToken refreshToken) {
		removeAccessTokenUsingRefreshToken(refreshToken.getValue());
	}

	@Override
	public OAuth2AccessToken getAccessToken(final OAuth2Authentication authentication) {
		OAuth2AccessToken accessToken = null;

		String authenticationKey = authenticationKeyGenerator.extractKey(authentication);

		final MongoOAuthAccessToken mongoAccessToken = this.mongoTemplate.findOne(
				findByAuthenticationId(authenticationKey), MongoOAuthAccessToken.class);

		if (mongoAccessToken != null) {
			accessToken = deserializeAccessToken(mongoAccessToken.getToken());
		}

		if (accessToken != null && !authenticationKey.equals(authenticationKeyGenerator
				.extractKey(readAuthentication(accessToken.getValue())))) {
			removeAccessToken(accessToken.getValue());
			// Keep the store consistent (maybe the same user is represented by this
			// authentication but the details have changed)
			storeAccessToken(accessToken, authentication);
		}
		return accessToken;
	}

	@Override
	public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(
			final String clientId, final String userName) {
		final List<MongoOAuthAccessToken> accessTokens = this.mongoTemplate.find(
				findByClientIdAndUsername(clientId, userName),
				MongoOAuthAccessToken.class);
		return oAuth2AccessTokens(accessTokens);
	}

	@Override
	public Collection<OAuth2AccessToken> findTokensByClientId(final String clientId) {
		final List<MongoOAuthAccessToken> accessTokens = this.mongoTemplate
				.find(findByClientId(clientId), MongoOAuthAccessToken.class);
		return oAuth2AccessTokens(accessTokens);
	}

	private Collection<OAuth2AccessToken> oAuth2AccessTokens(
			final Collection<MongoOAuthAccessToken> mongoAccessTokens) {
		Collection<OAuth2AccessToken> accessTokens = new ArrayList<OAuth2AccessToken>(
				mongoAccessTokens.size());
		for (MongoOAuthAccessToken accessToken : mongoAccessTokens) {
			accessTokens.add(deserializeAccessToken(accessToken.getToken()));
		}
		return accessTokens;
	}

	protected String extractTokenKey(final String value) {
		String tokenKey = null;
		if (value != null) {
			MessageDigest digest;
			try {
				digest = MessageDigest.getInstance("MD5");
			}
			catch (NoSuchAlgorithmException e) {
				throw new IllegalStateException(
						"MD5 algorithm not available.  Fatal (should be in the JDK).");
			}

			try {
				byte[] bytes = digest.digest(value.getBytes("UTF-8"));
				tokenKey = String.format("%032x", new BigInteger(1, bytes));
			}
			catch (UnsupportedEncodingException e) {
				throw new IllegalStateException(
						"UTF-8 encoding not available.  Fatal (should be in the JDK).");
			}
		}
		return tokenKey;
	}

	protected byte[] serializeAccessToken(final OAuth2AccessToken token) {
		return SerializationUtils.serialize(token);
	}

	protected byte[] serializeRefreshToken(final OAuth2RefreshToken token) {
		return SerializationUtils.serialize(token);
	}

	protected byte[] serializeAuthentication(final OAuth2Authentication authentication) {
		return SerializationUtils.serialize(authentication);
	}

	protected OAuth2AccessToken deserializeAccessToken(final byte[] token) {
		return SerializationUtils.deserialize(token);
	}

	protected OAuth2RefreshToken deserializeRefreshToken(final byte[] token) {
		return SerializationUtils.deserialize(token);
	}

	protected OAuth2Authentication deserializeAuthentication(
			final byte[] authentication) {
		return SerializationUtils.deserialize(authentication);
	}

	public OAuth2Authentication readAuthenticationForRefreshToken(final String value) {
		OAuth2Authentication authentication = null;
		final String tokenId = extractTokenKey(value);
		final MongoOAuthRefreshToken mongoRefreshToken = mongoTemplate
				.findOne(findByTokenId(tokenId), MongoOAuthRefreshToken.class);

		if (mongoRefreshToken != null) {
			try {
				authentication = deserializeAuthentication(
						mongoRefreshToken.getAuthentication());
			}
			catch (IllegalArgumentException e) {
				removeRefreshToken(value);
			}
		}

		return authentication;
	}

	public void removeRefreshToken(final String token) {
		final String tokenId = extractTokenKey(token);
		this.mongoTemplate.remove(findByTokenId(tokenId), MongoOAuthRefreshToken.class);
	}

	public void removeAccessTokenUsingRefreshToken(final String refreshToken) {
		final String tokenId = extractTokenKey(refreshToken);
		this.mongoTemplate.remove(findByTokenId(tokenId), MongoOAuthRefreshToken.class);
	}

	/**
	 * Creates a ${@link Query} to find by tokenId.
	 *
	 * @param tokenId The tokenId
	 * @return A ${@link Query}
	 */
	private Query findByTokenId(final String tokenId) {
		return new Query(Criteria.where(TOKEN_ID).is(tokenId));
	}

	/**
	 * Creates a Query to find by clientId.
	 *
	 * @param clientId The clientId
	 * @return A Query
	 */
	private Query findByClientId(final String clientId) {
		return new Query((Criteria.where(CLIENT_ID).is(clientId)));
	}

	/**
	 * Creates a Query to find by authenticationId.
	 *
	 * @param authenticationId The authenticationId
	 * @return A Query
	 */
	private Query findByAuthenticationId(final String authenticationId) {
		return new Query(Criteria.where(AUTHENTICATION_ID).is(authenticationId));
	}

	/**
	 * Creates a Query to find by clientId and username.
	 *
	 * @param clientId The clientId
	 * @param username The username
	 * @return Query
	 */
	private Query findByClientIdAndUsername(final String clientId,
			final String username) {
		return Query.query(Criteria.where(CLIENT_ID).is(clientId)
				.andOperator(Criteria.where(USER_NAME).is(username)));
	}

}
