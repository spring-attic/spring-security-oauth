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

import org.springframework.security.jwt.codec.Codecs;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A source for JSON Web Key(s) (JWK) that is solely responsible for fetching (and caching)
 * the JWK Set (a set of JWKs) from the URL supplied to the constructor.
 *
 * @see JwkSetConverter
 * @see JwkDefinition
 * @see SignatureVerifier
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7517#page-10">JWK Set Format</a>
 *
 * @author Joe Grandja
 */
class JwkDefinitionSource {
	private final URL jwkSetUrl;
	private final JwkSetConverter jwkSetConverter = new JwkSetConverter();
	private final AtomicReference<Map<JwkDefinition, SignatureVerifier>> jwkDefinitions =
			new AtomicReference<Map<JwkDefinition, SignatureVerifier>>(new HashMap<JwkDefinition, SignatureVerifier>());

	/**
	 * Creates a new instance using the provided URL as the location for the JWK Set.
	 *
	 * @param jwkSetUrl the JWK Set URL
	 */
	JwkDefinitionSource(String jwkSetUrl) {
		try {
			this.jwkSetUrl = new URL(jwkSetUrl);
		} catch (MalformedURLException ex) {
			throw new IllegalArgumentException("Invalid JWK Set URL: " + ex.getMessage(), ex);
		}
	}

	/**
	 * Returns the JWK definition matching the provided keyId (&quot;kid&quot;).
	 *
	 * @param keyId the Key ID (&quot;kid&quot;)
	 * @return the matching {@link JwkDefinition} or null if not found
	 */
	JwkDefinition getDefinition(String keyId) {
		JwkDefinition result = null;
		for (JwkDefinition jwkDefinition : this.jwkDefinitions.get().keySet()) {
			if (jwkDefinition.getKeyId().equals(keyId)) {
				result = jwkDefinition;
				break;
			}
		}
		return result;
	}

	/**
	 * Returns the JWK definition matching the provided keyId (&quot;kid&quot;).
	 * If the JWK definition is not available in the internal cache then {@link #refreshJwkDefinitions()}
	 * will be called (to refresh the cache) and then followed-up with a second attempt to locate the JWK definition.
	 *
	 * @param keyId the Key ID (&quot;kid&quot;)
	 * @return the matching {@link JwkDefinition} or null if not found
	 */
	JwkDefinition getDefinitionRefreshIfNecessary(String keyId) {
		JwkDefinition result = this.getDefinition(keyId);
		if (result != null) {
			return result;
		}
		this.refreshJwkDefinitions();
		return this.getDefinition(keyId);
	}

	/**
	 * Returns the {@link SignatureVerifier} matching the provided keyId (&quot;kid&quot;).
	 *
	 * @param keyId the Key ID (&quot;kid&quot;)
	 * @return the matching {@link SignatureVerifier} or null if not found
	 */
	SignatureVerifier getVerifier(String keyId) {
		SignatureVerifier result = null;
		JwkDefinition jwkDefinition = this.getDefinitionRefreshIfNecessary(keyId);
		if (jwkDefinition != null) {
			result = this.jwkDefinitions.get().get(jwkDefinition);
		}
		return result;
	}

	/**
	 * Refreshes the internal cache of association(s) between {@link JwkDefinition} and {@link SignatureVerifier}.
	 * Uses a {@link JwkSetConverter} to convert the JWK Set URL source to a set of {@link JwkDefinition}(s)
	 * followed by the instantiation of a {@link SignatureVerifier} which is mapped to it's {@link JwkDefinition}.
	 *
	 * @see JwkSetConverter
	 */
	void refreshJwkDefinitions() {
		InputStream jwkSetSource;
		try {
			jwkSetSource = this.jwkSetUrl.openStream();
		} catch (IOException ex) {
			throw new JwkException("An I/O error occurred while reading from the JWK Set source: " + ex.getMessage(), ex);
		}

		Set<JwkDefinition> jwkDefinitionSet = this.jwkSetConverter.convert(jwkSetSource);

		Map<JwkDefinition, SignatureVerifier> refreshedJwkDefinitions = new LinkedHashMap<JwkDefinition, SignatureVerifier>();

		for (JwkDefinition jwkDefinition : jwkDefinitionSet) {
			if (JwkDefinition.KeyType.RSA.equals(jwkDefinition.getKeyType())) {
				refreshedJwkDefinitions.put(jwkDefinition, this.createRSAVerifier((RSAJwkDefinition)jwkDefinition));
			}
		}

		this.jwkDefinitions.set(refreshedJwkDefinitions);
	}

	private RsaVerifier createRSAVerifier(RSAJwkDefinition rsaDefinition) {
		RsaVerifier result;
		try {
			BigInteger modulus = new BigInteger(Codecs.b64UrlDecode(rsaDefinition.getModulus()));
			BigInteger exponent = new BigInteger(Codecs.b64UrlDecode(rsaDefinition.getExponent()));

			RSAPublicKey rsaPublicKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
					.generatePublic(new RSAPublicKeySpec(modulus, exponent));

			result = new RsaVerifier(rsaPublicKey, rsaDefinition.getAlgorithm().standardName());

		} catch (Exception ex) {
			throw new JwkException("An error occurred while creating a RSA Public Key Verifier for " +
					rsaDefinition.getKeyId() + " : " + ex.getMessage(), ex);
		}
		return result;
	}
}
