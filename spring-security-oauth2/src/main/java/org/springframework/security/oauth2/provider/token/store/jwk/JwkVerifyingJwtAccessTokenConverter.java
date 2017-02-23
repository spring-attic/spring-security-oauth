/*
 * Copyright 2012-2016 the original author or authors.
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
package org.springframework.security.oauth2.provider.token.store.jwk;

import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import java.util.Map;

import static org.springframework.security.oauth2.provider.token.store.jwk.JwkAttributes.ALGORITHM;
import static org.springframework.security.oauth2.provider.token.store.jwk.JwkAttributes.KEY_ID;

/**
 * @author Joe Grandja
 */
class JwkVerifyingJwtAccessTokenConverter extends JwtAccessTokenConverter {
	private final JwkDefinitionSource jwkDefinitionSource;
	private final JwtHeaderConverter jwtHeaderConverter = new JwtHeaderConverter();
	private final JsonParser jsonParser = JsonParserFactory.create();

	JwkVerifyingJwtAccessTokenConverter(JwkDefinitionSource jwkDefinitionSource) {
		this.jwkDefinitionSource = jwkDefinitionSource;
	}

	@Override
	protected Map<String, Object> decode(String token) {
		try {
			Map<String, String> headers = this.jwtHeaderConverter.convert(token);

			// Validate "kid" header
			String keyIdHeader = headers.get(KEY_ID);
			if (keyIdHeader == null) {
				throw new JwkException("Invalid JWT/JWS: \"" + KEY_ID + "\" is a required JOSE Header.");
			}
			JwkDefinition jwkDefinition = this.jwkDefinitionSource.getDefinitionRefreshIfNecessary(keyIdHeader);
			if (jwkDefinition == null) {
				throw new JwkException("Invalid JOSE Header \"" + KEY_ID + "\" (" + keyIdHeader + ")");
			}

			// Validate "alg" header
			String algorithmHeader = headers.get(ALGORITHM);
			if (algorithmHeader == null) {
				throw new JwkException("Invalid JWT/JWS: \"" + ALGORITHM + "\" is a required JOSE Header.");
			}
			if (!algorithmHeader.equals(jwkDefinition.getAlgorithm().headerParamValue())) {
				throw new JwkException("Invalid JOSE Header \"" + ALGORITHM + "\" (" + algorithmHeader + ")" +
						" does not match algorithm associated with \"" + KEY_ID + "\" (" + keyIdHeader + ")");
			}

			// Verify signature
			SignatureVerifier verifier = this.jwkDefinitionSource.getVerifier(keyIdHeader);
			Jwt jwt = JwtHelper.decode(token);
			jwt.verifySignature(verifier);

			Map<String, Object> claims = this.jsonParser.parseMap(jwt.getClaims());
			if (claims.containsKey(EXP) && claims.get(EXP) instanceof Integer) {
				Integer expiryInt = (Integer) claims.get(EXP);
				claims.put(EXP, new Long(expiryInt));
			}

			return claims;

		} catch (Exception ex) {
			throw new JwkException("Failed to decode/verify the JWT/JWS: " + ex.getMessage(), ex);
		}
	}

	@Override
	protected String encode(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
		throw new JwkException("JWT/JWS (signing) is currently not supported.");
	}
}