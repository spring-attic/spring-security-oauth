package org.springframework.security.oauth2.client.token.mongo;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceConstructor;
import org.springframework.data.mongodb.core.mapping.Document;

/**
 * @author Marcos Barbero
 */
@Document(collection = "oauth_client_token")
public class MongoOAuthClientToken {

	@Id
	private String id;
	private String tokenId;
	private byte[] token;
	private String authenticationId;
	private String username;
	private String clientId;

	public MongoOAuthClientToken() {
	}

	@PersistenceConstructor
	public MongoOAuthClientToken(final String id, final String tokenId,
			final byte[] token, final String authenticationId, final String username,
			final String clientId) {
		this.id = id;
		this.tokenId = tokenId;
		this.token = token;
		this.authenticationId = authenticationId;
		this.username = username;
		this.clientId = clientId;
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
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

	public String getAuthenticationId() {
		return authenticationId;
	}

	public void setAuthenticationId(String authenticationId) {
		this.authenticationId = authenticationId;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}
}
