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
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

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
	private final List<URL> jwkSetUrls;
	private final Map<String, JwkDefinitionHolder> jwkDefinitions = new ConcurrentHashMap<String, JwkDefinitionHolder>();
	private static final JwkSetConverter jwkSetConverter = new JwkSetConverter();

	/**
	 * Creates a new instance using the provided URL as the location for the JWK Set.
	 *
	 * @param jwkSetUrl the JWK Set URL
	 */
	JwkDefinitionSource(String jwkSetUrl) {
		this(Arrays.asList(jwkSetUrl));
	}

	/**
	 * Creates a new instance using the provided URLs as the location for the JWK Sets.
	 *
	 * @param jwkSetUrls the JWK Set URLs
	 */
	JwkDefinitionSource(List<String> jwkSetUrls) {
		this.jwkSetUrls = new ArrayList<URL>();
		for(String jwkSetUrl : jwkSetUrls) {
			try {
				this.jwkSetUrls.add(new URL(jwkSetUrl));
			} catch (MalformedURLException ex) {
				throw new IllegalArgumentException("Invalid JWK Set URL: " + ex.getMessage(), ex);
			}
		}
	}

	/**
	 * Returns the JWK definition matching the provided keyId (&quot;kid&quot;).
	 * If the JWK definition is not available in the internal cache then {@link #loadJwkDefinitions(URL)}
	 * will be called (to re-load the cache) and then followed-up with a second attempt to locate the JWK definition.
	 *
	 * @param keyId the Key ID (&quot;kid&quot;)
	 * @return the matching {@link JwkDefinition} or null if not found
	 */
	JwkDefinitionHolder getDefinitionLoadIfNecessary(String keyId) {
		JwkDefinitionHolder result = this.getDefinition(keyId);
		if (result != null) {
			return result;
		}
		synchronized (this.jwkDefinitions) {
			this.jwkDefinitions.clear();
			for (URL jwkSetUrl : jwkSetUrls) {
				this.jwkDefinitions.putAll(loadJwkDefinitions(jwkSetUrl));
			}
			return this.getDefinition(keyId);
		}
	}

	/**
	 * Returns the JWK definition matching the provided keyId (&quot;kid&quot;).
	 *
	 * @param keyId the Key ID (&quot;kid&quot;)
	 * @return the matching {@link JwkDefinition} or null if not found
	 */
	private JwkDefinitionHolder getDefinition(String keyId) {
		return this.jwkDefinitions.get(keyId);
	}

	/**
	 * Fetches the JWK Set from the provided <code>URL</code> and
	 * returns a <code>Map</code> keyed by the JWK keyId (&quot;kid&quot;)
	 * and mapped to an association of the {@link JwkDefinition} and {@link SignatureVerifier}.
	 * Uses a {@link JwkSetConverter} to convert the JWK Set URL source to a set of {@link JwkDefinition}(s)
	 * followed by the instantiation of a {@link SignatureVerifier} which is associated to it's {@link JwkDefinition}.
	 *
	 * @param jwkSetUrl the JWK Set URL
	 * @return a <code>Map</code> keyed by the JWK keyId and mapped to an association of {@link JwkDefinition} and {@link SignatureVerifier}
	 * @see JwkSetConverter
	 */
	static Map<String, JwkDefinitionHolder> loadJwkDefinitions(URL jwkSetUrl) {
		InputStream jwkSetSource;
		try {
			jwkSetSource = jwkSetUrl.openStream();
		} catch (IOException ex) {
			throw new JwkException("An I/O error occurred while reading from the JWK Set source: " + ex.getMessage(), ex);
		}

		Set<JwkDefinition> jwkDefinitionSet = jwkSetConverter.convert(jwkSetSource);

		Map<String, JwkDefinitionHolder> jwkDefinitions = new LinkedHashMap<String, JwkDefinitionHolder>();

		for (JwkDefinition jwkDefinition : jwkDefinitionSet) {
			if (JwkDefinition.KeyType.RSA.equals(jwkDefinition.getKeyType())) {
				jwkDefinitions.put(jwkDefinition.getKeyId(),
						new JwkDefinitionHolder(jwkDefinition, createRsaVerifier((RsaJwkDefinition) jwkDefinition)));
			}
		}

		return jwkDefinitions;
	}

	private static RsaVerifier createRsaVerifier(RsaJwkDefinition rsaDefinition) {
		RsaVerifier result;
		try {
			BigInteger modulus = new BigInteger(1, Codecs.b64UrlDecode(rsaDefinition.getModulus()));
			BigInteger exponent = new BigInteger(1, Codecs.b64UrlDecode(rsaDefinition.getExponent()));

			RSAPublicKey rsaPublicKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
					.generatePublic(new RSAPublicKeySpec(modulus, exponent));

			if (rsaDefinition.getAlgorithm() != null) {
				result = new RsaVerifier(rsaPublicKey, rsaDefinition.getAlgorithm().standardName());
			} else {
				result = new RsaVerifier(rsaPublicKey);
			}

		} catch (Exception ex) {
			throw new JwkException("An error occurred while creating a RSA Public Key Verifier for " +
					rsaDefinition.getKeyId() + " : " + ex.getMessage(), ex);
		}
		return result;
	}

	static class JwkDefinitionHolder {
		private final JwkDefinition jwkDefinition;
		private final SignatureVerifier signatureVerifier;

		private JwkDefinitionHolder(JwkDefinition jwkDefinition, SignatureVerifier signatureVerifier) {
			this.jwkDefinition = jwkDefinition;
			this.signatureVerifier = signatureVerifier;
		}

		JwkDefinition getJwkDefinition() {
			return jwkDefinition;
		}

		SignatureVerifier getSignatureVerifier() {
			return signatureVerifier;
		}
	}
}