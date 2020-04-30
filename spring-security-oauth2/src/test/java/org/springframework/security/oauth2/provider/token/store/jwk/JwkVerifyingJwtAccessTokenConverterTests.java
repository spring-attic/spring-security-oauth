/*
 * Copyright 2012-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.provider.token.store.jwk;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;

import java.util.Map;

import static org.junit.Assert.assertNotNull;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.jwt.codec.Codecs.b64UrlEncode;
import static org.springframework.security.jwt.codec.Codecs.utf8Decode;
import static org.springframework.security.oauth2.provider.token.store.jwk.JwtTestUtil.createJwt;
import static org.springframework.security.oauth2.provider.token.store.jwk.JwtTestUtil.createJwtHeader;

/**
 * @author Joe Grandja
 */
public class JwkVerifyingJwtAccessTokenConverterTests {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Test
	public void encodeWhenCalledThenThrowJwkException() throws Exception {
		this.thrown.expect(JwkException.class);
		this.thrown.expectMessage("JWT signing (JWS) is not supported.");
		JwkVerifyingJwtAccessTokenConverter accessTokenConverter =
				new JwkVerifyingJwtAccessTokenConverter(mock(JwkDefinitionSource.class));
		accessTokenConverter.encode(null, null);
	}

	@Test
	public void decodeWhenKeyIdHeaderMissingThenThrowJwkException() throws Exception {
		this.thrown.expect(InvalidTokenException.class);
		this.thrown.expectMessage("Invalid JWT/JWS: kid or x5t is a required JOSE Header");
		JwkVerifyingJwtAccessTokenConverter accessTokenConverter =
				new JwkVerifyingJwtAccessTokenConverter(mock(JwkDefinitionSource.class));
		String jwt = createJwt(createJwtHeader(null, null, JwkDefinition.CryptoAlgorithm.RS256));
		accessTokenConverter.decode(jwt);
	}

	@Test
	public void decodeWhenKeyIdHeaderInvalidThenThrowJwkException() throws Exception {
		this.thrown.expect(InvalidTokenException.class);
		this.thrown.expectMessage("Invalid JOSE Header kid (invalid-key-id), x5t (null)");
		JwkDefinition jwkDefinition = this.createRSAJwkDefinition("key-id-1", null, JwkDefinition.CryptoAlgorithm.RS256);
		JwkDefinitionSource jwkDefinitionSource = mock(JwkDefinitionSource.class);
		JwkDefinitionSource.JwkDefinitionHolder jwkDefinitionHolder = mock(JwkDefinitionSource.JwkDefinitionHolder.class);
		when(jwkDefinitionHolder.getJwkDefinition()).thenReturn(jwkDefinition);
		when(jwkDefinitionSource.getDefinitionLoadIfNecessary("key-id-1", null)).thenReturn(jwkDefinitionHolder);
		JwkVerifyingJwtAccessTokenConverter accessTokenConverter =
				new JwkVerifyingJwtAccessTokenConverter(jwkDefinitionSource);
		String jwt = createJwt(createJwtHeader("invalid-key-id", null, JwkDefinition.CryptoAlgorithm.RS256));
		accessTokenConverter.decode(jwt);
	}

	// gh-1129
	@Test
	public void decodeWhenJwkAlgorithmNullAndJwtAlgorithmPresentThenDecodeStillSucceeds() throws Exception {
		JwkDefinition jwkDefinition = this.createRSAJwkDefinition("key-id-1", null, null);
		JwkDefinitionSource jwkDefinitionSource = mock(JwkDefinitionSource.class);
		JwkDefinitionSource.JwkDefinitionHolder jwkDefinitionHolder = mock(JwkDefinitionSource.JwkDefinitionHolder.class);
		SignatureVerifier signatureVerifier = mock(SignatureVerifier.class);
		when(jwkDefinitionHolder.getJwkDefinition()).thenReturn(jwkDefinition);
		when(jwkDefinitionSource.getDefinitionLoadIfNecessary("key-id-1", null)).thenReturn(jwkDefinitionHolder);
		when(jwkDefinitionHolder.getSignatureVerifier()).thenReturn(signatureVerifier);
		JwkVerifyingJwtAccessTokenConverter accessTokenConverter =
				new JwkVerifyingJwtAccessTokenConverter(jwkDefinitionSource);
		String jwt = createJwt(createJwtHeader("key-id-1", null, JwkDefinition.CryptoAlgorithm.RS256));
		String jws = jwt + "." + utf8Decode(b64UrlEncode("junkSignature".getBytes()));
		Map<String, Object> decodedJwt = accessTokenConverter.decode(jws);
		assertNotNull(decodedJwt);
	}

	@Test
	public void decodeWhenAlgorithmHeaderMissingThenThrowJwkException() throws Exception {
		this.thrown.expect(InvalidTokenException.class);
		this.thrown.expectMessage("Invalid JWT/JWS: alg is a required JOSE Header");
		JwkDefinition jwkDefinition = this.createRSAJwkDefinition("key-id-1", null, JwkDefinition.CryptoAlgorithm.RS256);
		JwkDefinitionSource jwkDefinitionSource = mock(JwkDefinitionSource.class);
		JwkDefinitionSource.JwkDefinitionHolder jwkDefinitionHolder = mock(JwkDefinitionSource.JwkDefinitionHolder.class);
		when(jwkDefinitionHolder.getJwkDefinition()).thenReturn(jwkDefinition);
		when(jwkDefinitionSource.getDefinitionLoadIfNecessary("key-id-1", null)).thenReturn(jwkDefinitionHolder);
		JwkVerifyingJwtAccessTokenConverter accessTokenConverter =
				new JwkVerifyingJwtAccessTokenConverter(jwkDefinitionSource);
		String jwt = createJwt(createJwtHeader("key-id-1", null, null));
		accessTokenConverter.decode(jwt);
	}

	@Test
	public void decodeWhenAlgorithmHeaderDoesNotMatchJwkAlgorithmThenThrowJwkException() throws Exception {
		this.thrown.expect(InvalidTokenException.class);
		this.thrown.expectMessage("Invalid JOSE Header alg (RS512) " +
				"does not match algorithm associated to JWK with kid (key-id-1)");
		JwkDefinition jwkDefinition = this.createRSAJwkDefinition("key-id-1", null, JwkDefinition.CryptoAlgorithm.RS256);
		JwkDefinitionSource jwkDefinitionSource = mock(JwkDefinitionSource.class);
		JwkDefinitionSource.JwkDefinitionHolder jwkDefinitionHolder = mock(JwkDefinitionSource.JwkDefinitionHolder.class);
		when(jwkDefinitionHolder.getJwkDefinition()).thenReturn(jwkDefinition);
		when(jwkDefinitionSource.getDefinitionLoadIfNecessary("key-id-1", null)).thenReturn(jwkDefinitionHolder);
		JwkVerifyingJwtAccessTokenConverter accessTokenConverter =
				new JwkVerifyingJwtAccessTokenConverter(jwkDefinitionSource);
		String jwt = createJwt(createJwtHeader("key-id-1", null, JwkDefinition.CryptoAlgorithm.RS512));
		accessTokenConverter.decode(jwt);
	}

	@Test
	public void decodeWhenKidHeaderMissingButX5tHeaderPresentThenDecodeStillSucceeds() throws Exception {
		JwkDefinition jwkDefinition = this.createRSAJwkDefinition("key-id-1", "x5t-1", null);
		JwkDefinitionSource jwkDefinitionSource = mock(JwkDefinitionSource.class);
		JwkDefinitionSource.JwkDefinitionHolder jwkDefinitionHolder = mock(JwkDefinitionSource.JwkDefinitionHolder.class);
		SignatureVerifier signatureVerifier = mock(SignatureVerifier.class);
		when(jwkDefinitionHolder.getJwkDefinition()).thenReturn(jwkDefinition);
		when(jwkDefinitionSource.getDefinitionLoadIfNecessary(null, "x5t-1")).thenReturn(jwkDefinitionHolder);
		when(jwkDefinitionHolder.getSignatureVerifier()).thenReturn(signatureVerifier);
		JwkVerifyingJwtAccessTokenConverter accessTokenConverter =
				new JwkVerifyingJwtAccessTokenConverter(jwkDefinitionSource);
		String jwt = createJwt(createJwtHeader(null, "x5t-1", JwkDefinition.CryptoAlgorithm.RS256));
		String jws = jwt + "." + utf8Decode(b64UrlEncode("junkSignature".getBytes()));
		Map<String, Object> decodedJwt = accessTokenConverter.decode(jws);
		assertNotNull(decodedJwt);
	}

	// gh-1522, gh-1852
	@Test
	public void decodeWhenVerifySignatureFailsThenThrowInvalidTokenException() throws Exception {
		this.thrown.expect(InvalidTokenException.class);
		this.thrown.expectMessage("Failed to decode/verify JWT/JWS");
		JwkDefinition jwkDefinition = this.createRSAJwkDefinition("key-id-1", null, null);
		JwkDefinitionSource jwkDefinitionSource = mock(JwkDefinitionSource.class);
		JwkDefinitionSource.JwkDefinitionHolder jwkDefinitionHolder = mock(JwkDefinitionSource.JwkDefinitionHolder.class);
		SignatureVerifier signatureVerifier = mock(SignatureVerifier.class);
		when(jwkDefinitionHolder.getJwkDefinition()).thenReturn(jwkDefinition);
		when(jwkDefinitionSource.getDefinitionLoadIfNecessary("key-id-1", null)).thenReturn(jwkDefinitionHolder);
		when(jwkDefinitionHolder.getSignatureVerifier()).thenReturn(signatureVerifier);
		doThrow(RuntimeException.class).when(signatureVerifier).verify(any(byte[].class), any(byte[].class));
		JwkVerifyingJwtAccessTokenConverter accessTokenConverter =
				new JwkVerifyingJwtAccessTokenConverter(jwkDefinitionSource);
		String jwt = createJwt(createJwtHeader("key-id-1", null, JwkDefinition.CryptoAlgorithm.RS256));
		String jws = jwt + "." + utf8Decode(b64UrlEncode("junkSignature".getBytes()));
		accessTokenConverter.decode(jws);
	}

	private JwkDefinition createRSAJwkDefinition(String keyId, String x5t, JwkDefinition.CryptoAlgorithm algorithm) {
		return createRSAJwkDefinition(JwkDefinition.KeyType.RSA, keyId, x5t,
				JwkDefinition.PublicKeyUse.SIG, algorithm, "AMh-pGAj9vX2gwFDyrXot1f2YfHgh8h0Qx6w9IqLL", "AQAB");
	}

	private JwkDefinition createRSAJwkDefinition(JwkDefinition.KeyType keyType,
												String keyId,
												String x5t,
												JwkDefinition.PublicKeyUse publicKeyUse,
												JwkDefinition.CryptoAlgorithm algorithm,
												String modulus,
												String exponent) {

		return new RsaJwkDefinition(keyId, x5t, publicKeyUse, algorithm, modulus, exponent);
	}
}