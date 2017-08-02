/*
 * Copyright 2012-2017 the original author or authors.
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
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import java.util.Map;

import static org.springframework.security.oauth2.provider.token.store.jwk.JwkAttributes.ALGORITHM;
import static org.springframework.security.oauth2.provider.token.store.jwk.JwkAttributes.KEY_ID;

/**
 * A specialized extension of {@link JwtAccessTokenConverter} that is responsible for verifying
 * the JSON Web Signature (JWS) for a JSON Web Token (JWT) using the corresponding JSON Web Key (JWK).
 * This implementation is associated with a {@link JwkDefinitionSource} for looking up
 * the matching {@link JwkDefinition} using the value of the JWT header parameter <b>&quot;kid&quot;</b>.
 * <br>
 * <br>
 *
 * The JWS is verified in the following step sequence:
 * <br>
 * <br>
 * <ol>
 *     <li>Extract the <b>&quot;kid&quot;</b> parameter from the JWT header.</li>
 *     <li>Find the matching {@link JwkDefinition} from the {@link JwkDefinitionSource} with the corresponding <b>&quot;kid&quot;</b> attribute.</li>
 *     <li>Obtain the {@link SignatureVerifier} associated with the {@link JwkDefinition} via the {@link JwkDefinitionSource} and verify the signature.</li>
 * </ol>
 * <br>
 * <b>NOTE:</b> The algorithms currently supported by this implementation are: RS256, RS384 and RS512.
 * <br>
 * <br>
 *
 * <b>NOTE:</b> This {@link JwtAccessTokenConverter} <b>does not</b> support signing JWTs (JWS) and therefore
 * the {@link #encode(OAuth2AccessToken, OAuth2Authentication)} method implementation, if called,
 * will explicitly throw a {@link JwkException} reporting <i>&quot;JWT signing (JWS) is not supported.&quot;</i>.
 * <br>
 * <br>
 *
 * @see JwtAccessTokenConverter
 * @see JwtHeaderConverter
 * @see JwkDefinitionSource
 * @see JwkDefinition
 * @see SignatureVerifier
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7517">JSON Web Key (JWK)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7519">JSON Web Token (JWT)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515">JSON Web Signature (JWS)</a>
 *
 * @author Joe Grandja
 */
class JwkVerifyingJwtAccessTokenConverter extends JwtAccessTokenConverter {
	private final JwkDefinitionSource jwkDefinitionSource;
	private final JwtHeaderConverter jwtHeaderConverter = new JwtHeaderConverter();
	private final JsonParser jsonParser = JsonParserFactory.create();

	/**
	 * Creates a new instance using the provided {@link JwkDefinitionSource}
	 * as the primary source for looking up {@link JwkDefinition}(s).
	 *
	 * @param jwkDefinitionSource the source for {@link JwkDefinition}(s)
	 */
	JwkVerifyingJwtAccessTokenConverter(JwkDefinitionSource jwkDefinitionSource) {
		this.jwkDefinitionSource = jwkDefinitionSource;
	}

	/**
	 * Decodes and validates the supplied JWT followed by signature verification
	 * before returning the Claims from the JWT Payload.
	 *
	 * @param token the JSON Web Token
	 * @return a <code>Map</code> of the JWT Claims
	 * @throws JwkException if the JWT is invalid or if the JWS could not be verified
	 */
	@Override
	protected Map<String, Object> decode(String token) {
		Map<String, String> headers = this.jwtHeaderConverter.convert(token);

		// Validate "kid" header
		String keyIdHeader = headers.get(KEY_ID);
		if (keyIdHeader == null) {
			throw new InvalidTokenException("Invalid JWT/JWS: " + KEY_ID + " is a required JOSE Header");
		}
		JwkDefinitionSource.JwkDefinitionHolder jwkDefinitionHolder = this.jwkDefinitionSource.getDefinitionLoadIfNecessary(keyIdHeader);
		if (jwkDefinitionHolder == null) {
			throw new InvalidTokenException("Invalid JOSE Header " + KEY_ID + " (" + keyIdHeader + ")");
		}

		JwkDefinition jwkDefinition = jwkDefinitionHolder.getJwkDefinition();
		// Validate "alg" header
		String algorithmHeader = headers.get(ALGORITHM);
		if (algorithmHeader == null) {
			throw new InvalidTokenException("Invalid JWT/JWS: " + ALGORITHM + " is a required JOSE Header");
		}
		if (jwkDefinition.getAlgorithm() != null && !algorithmHeader.equals(jwkDefinition.getAlgorithm().headerParamValue())) {
			throw new InvalidTokenException("Invalid JOSE Header " + ALGORITHM + " (" + algorithmHeader + ")" +
					" does not match algorithm associated to JWK with " + KEY_ID + " (" + keyIdHeader + ")");
		}

		// Verify signature
		SignatureVerifier verifier = jwkDefinitionHolder.getSignatureVerifier();
		Jwt jwt = JwtHelper.decode(token);
		jwt.verifySignature(verifier);

		Map<String, Object> claims = this.jsonParser.parseMap(jwt.getClaims());
		if (claims.containsKey(EXP) && claims.get(EXP) instanceof Integer) {
			Integer expiryInt = (Integer) claims.get(EXP);
			claims.put(EXP, new Long(expiryInt));
		}
		this.getJwtClaimsSetVerifier().verify(claims);

		return claims;
	}

	/**
	 * This operation (JWT signing) is not supported and if called,
	 * will throw a {@link JwkException}.
	 *
	 * @throws JwkException
	 */
	@Override
	protected String encode(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
		throw new JwkException("JWT signing (JWS) is not supported.");
	}
}