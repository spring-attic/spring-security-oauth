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
import java.util.Map;
import java.util.Set;

import org.codehaus.jackson.JsonGenerationException;
import org.codehaus.jackson.JsonGenerator;
import org.codehaus.jackson.map.JsonSerializer;
import org.codehaus.jackson.map.SerializerProvider;
import org.codehaus.jackson.map.ser.SerializerBase;
import org.springframework.util.Assert;

/**
 * Provides the ability to serialize an {@link OAuth2AccessToken} with jackson by implementing {@link JsonSerializer}.
 * Refer to {@link OAuth2AccessTokenJackson1Deserializer} to learn more about the JSON format that is used.
 * 
 * @author Rob Winch
 * @see OAuth2AccessTokenJackson1Deserializer
 */
@SuppressWarnings("deprecation")
public final class OAuth2AccessTokenJackson1Serializer extends SerializerBase<OAuth2AccessToken> {

	public OAuth2AccessTokenJackson1Serializer() {
		super(OAuth2AccessToken.class);
	}

	@Override
	public void serialize(OAuth2AccessToken token, JsonGenerator jgen, SerializerProvider provider) throws IOException,
			JsonGenerationException {
		jgen.writeStartObject();
		jgen.writeStringField(OAuth2AccessToken.ACCESS_TOKEN, token.getValue());
		jgen.writeStringField(OAuth2AccessToken.TOKEN_TYPE, token.getTokenType());
		OAuth2RefreshToken refreshToken = token.getRefreshToken();
		if (refreshToken != null) {
			jgen.writeStringField(OAuth2AccessToken.REFRESH_TOKEN, refreshToken.getValue());
		}
		Date expiration = token.getExpiration();
		if (expiration != null) {
			long now = System.currentTimeMillis();
			jgen.writeNumberField(OAuth2AccessToken.EXPIRES_IN, (expiration.getTime() - now) / 1000);
		}
		Set<String> scope = token.getScope();
		if (scope != null && !scope.isEmpty()) {
			StringBuffer scopes = new StringBuffer();
			for (String s : scope) {
				Assert.hasLength(s, "Scopes cannot be null or empty. Got " + scope + "");
				scopes.append(s);
				scopes.append(" ");
			}
			jgen.writeStringField(OAuth2AccessToken.SCOPE, scopes.substring(0, scopes.length() - 1));
		}
		Map<String, Object> additionalInformation = token.getAdditionalInformation();
		for (String key : additionalInformation.keySet()) {
			jgen.writeObjectField(key, additionalInformation.get(key));
		}
		jgen.writeEndObject();
	}
}