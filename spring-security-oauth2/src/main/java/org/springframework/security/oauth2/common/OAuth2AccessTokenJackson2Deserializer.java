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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.springframework.security.oauth2.common.util.OAuth2Utils;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

/**
 * <p>
 * Provides the ability to deserialize JSON response into an {@link org.springframework.security.oauth2.common.OAuth2AccessToken} with jackson2 by implementing
 * {@link com.fasterxml.jackson.databind.JsonDeserializer}.
 * </p>
 * <p>
 * The expected format of the access token is defined by <a
 * href="http://tools.ietf.org/html/draft-ietf-oauth-v2-22#section-5.1">Successful Response</a>.
 * </p>
 *
 * @author Rob Winch
 * @author Brian Clozel
 * @see org.springframework.security.oauth2.common.OAuth2AccessTokenJackson2Serializer
 */
@SuppressWarnings("serial")
public final class OAuth2AccessTokenJackson2Deserializer extends StdDeserializer<OAuth2AccessToken> {

	public OAuth2AccessTokenJackson2Deserializer() {
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
		Map<String, Object> additionalInformation = new LinkedHashMap<String, Object>();

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
				try {
					expiresIn = jp.getLongValue();
				} catch (JsonParseException e) {
					expiresIn = Long.valueOf(jp.getText());
				}
			}
			else if (OAuth2AccessToken.SCOPE.equals(name)) {
				String text = jp.getText();
				scope = OAuth2Utils.parseParameterList(text);
			} else {
				additionalInformation.put(name, jp.readValueAs(Object.class));
			}
		}

		// TODO What should occur if a required parameter (tokenValue or tokenType) is missing?

		DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken(tokenValue);
		accessToken.setTokenType(tokenType);
		if (expiresIn != null) {
			accessToken.setExpiration(new Date(System.currentTimeMillis() + (expiresIn * 1000)));
		}
		if (refreshToken != null) {
			accessToken.setRefreshToken(new DefaultOAuth2RefreshToken(refreshToken));
		}
		accessToken.setScope(scope);
		accessToken.setAdditionalInformation(additionalInformation);

		return accessToken;
	}
}