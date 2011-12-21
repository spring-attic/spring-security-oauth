/*
 * Copyright 2006-2010 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.oauth2.common;

import java.io.IOException;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.codehaus.jackson.JsonParser;
import org.codehaus.jackson.JsonProcessingException;
import org.codehaus.jackson.JsonToken;
import org.codehaus.jackson.map.DeserializationContext;
import org.codehaus.jackson.map.JsonDeserializer;
import org.codehaus.jackson.map.deser.StdDeserializer;

/**
 * <p>
 * Provides the ability to deserialize JSON response into an {@link OAuth2AccessToken} with jackson by implementing
 * {@link JsonDeserializer}.
 * </p>
 * <p>
 * The expected format of the access token is defined by <a
 * href="http://tools.ietf.org/html/draft-ietf-oauth-v2-22#section-5.1">Successful Response</a>.
 * </p>
 *
 * @author Rob Winch
 * @see OAuth2AccessTokenDeserializer
 */
@SuppressWarnings("deprecation")
public final class OAuth2AccessTokenDeserializer extends StdDeserializer<OAuth2AccessToken> {

	public OAuth2AccessTokenDeserializer() {
		super(OAuth2AccessToken.class);
	}

	@Override
	public OAuth2AccessToken deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException,
			JsonProcessingException {

		String tokenValue = null;
		String tokenType = null;
		String refreshToken = null;
		Long expiresIn = null;
		Set<String> scope = null;

		// TODO What should occur if a parameter exists twice
		while (jp.nextToken() != JsonToken.END_OBJECT) {
			String name = jp.getCurrentName();
			jp.nextToken();
			if (OAuth2AccessToken.ACCESS_TOKEN.equals(name)) {
				tokenValue = jp.getText();
			}
			else if (OAuth2AccessToken.TOKEN_TYPE.equals(name)) {
				tokenType = jp.getText();
			}
			else if (OAuth2AccessToken.REFRESH_TOKEN.equals(name)) {
				refreshToken = jp.getText();
			}
			else if (OAuth2AccessToken.EXPIRES_IN.equals(name)) {
				expiresIn = jp.getLongValue();
			}
			else if (OAuth2AccessToken.SCOPE.equals(name)) {
				String text = jp.getText();
				scope = new HashSet<String>();
				// The spec is not really clear about an empty String value for scope, so we will just choose to have
				// an empty Set in this instance
				if (!"".equals(text)) {
					for (String s : text.split(" ")) {
						scope.add(s);
					}
				}
			} else {
				// http://tools.ietf.org/html/draft-ietf-oauth-v2-22#section-5.1
				// the spec states to ignore unknown response parameters
			}
		}

		// TODO What should occur if a required parameter (tokenValue or tokenType) is missing?

		OAuth2AccessToken accessToken = new OAuth2AccessToken(tokenValue);
		accessToken.setTokenType(tokenType);
		if (expiresIn != null) {
			accessToken.setExpiration(new Date(System.currentTimeMillis() + (expiresIn * 1000)));
		}
		if (refreshToken != null) {
			accessToken.setRefreshToken(new OAuth2RefreshToken(refreshToken));
		}
		accessToken.setScope(scope);

		return accessToken;
	}
}