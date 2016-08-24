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

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceConstructor;
import org.springframework.data.mongodb.core.mapping.Document;

/**
 * @author Marcos Barbero
 */
@Document(collection = "oauth_access_token")
public class MongoOAuthAccessToken {

	@Id
	private String tokenId;

	private byte[] token;

	private String authenticationId;

	private String userName;

	private String clientId;

	private byte[] authentication;

	private String refreshTokenId;

	public MongoOAuthAccessToken() {
	}

	@PersistenceConstructor
	public MongoOAuthAccessToken(String tokenId, byte[] token, String authenticationId,
			String userName, String clientId, byte[] authentication,
			String refreshTokenId) {
		this.tokenId = tokenId;
		this.token = token;
		this.authenticationId = authenticationId;
		this.userName = userName;
		this.clientId = clientId;
		this.authentication = authentication;
		this.refreshTokenId = refreshTokenId;
	}

	public String getTokenId() {
		return tokenId;
	}

	public void setTokenId(String tokenId) {
		this.tokenId = tokenId;
	}

	public byte[] getToken() {
		return this.token;
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

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public byte[] getAuthentication() {
		return authentication;
	}

	public void setAuthentication(byte[] authentication) {
		this.authentication = authentication;
	}

	public String getRefreshTokenId() {
		return refreshTokenId;
	}

	public void setRefreshTokenId(String refreshTokenId) {
		this.refreshTokenId = refreshTokenId;
	}
}
