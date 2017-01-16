package org.springframework.security.oauth2.provider.token.store.mongo;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceConstructor;
import org.springframework.data.mongodb.core.mapping.Document;

/**
 * @author Marcos Barbero
 */
@Document(collection = "oauth_refresh_token")
public class MongoOAuthRefreshToken {

	@Id
	private String tokenId;
	private byte[] token;
	private byte[] authentication;

	public MongoOAuthRefreshToken() {
	}

	@PersistenceConstructor
	public MongoOAuthRefreshToken(final String tokenId, final byte[] token,
			final byte[] authentication) {
		this.tokenId = tokenId;
		this.token = token;
		this.authentication = authentication;
	}

	public String getTokenId() {
		return tokenId;
	}

	public void setTokenId(String tokenId) {
		this.tokenId = tokenId;
	}

	public byte[] getToken() {
		return token;
	}

	public void setToken(byte[] token) {
		this.token = token;
	}

	public byte[] getAuthentication() {
		return authentication;
	}

	public void setAuthentication(byte[] authentication) {
		this.authentication = authentication;
	}
}
