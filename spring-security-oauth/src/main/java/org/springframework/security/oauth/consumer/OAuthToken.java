/*
 * Copyright 2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth.consumer;

import java.io.Serializable;

/**
 * Holds an OAuth token and secret.
 * Used for both the request token and access token.
 * The secret is null for OAuth2-based connections.
 * @author Keith Donald
 */
public final class OAuthToken implements Serializable {

	private final String value;
	
	private final String secret;
	
	/**
	 * Create a new OAuth token with a token value and secret.
	 */
	public OAuthToken(String value, String secret) {
		this.value = value;
		this.secret = secret;
	}
	
	public String getValue() {
		return value;
	}

	public String getSecret() {
		return secret;
	}

}
