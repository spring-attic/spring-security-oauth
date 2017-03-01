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

/**
 * A JSON Web Key (JWK) representation of a RSA key.
 *
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7517">JSON Web Key (JWK)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7518#page-30">JSON Web Algorithms (JWA)</a>
 *
 * @author Joe Grandja
 */
final class RsaJwkDefinition extends JwkDefinition {
	private final String modulus;
	private final String exponent;

	/**
	 * Creates an instance of a RSA JSON Web Key (JWK).
	 *
	 * @param keyId the Key ID
	 * @param publicKeyUse the intended use of the Public Key
	 * @param algorithm the algorithm intended to be used
	 * @param modulus the modulus value for the Public Key
	 * @param exponent the exponent value for the Public Key
	 */
	RsaJwkDefinition(String keyId,
					 PublicKeyUse publicKeyUse,
					 CryptoAlgorithm algorithm,
					 String modulus,
					 String exponent) {

		super(keyId, KeyType.RSA, publicKeyUse, algorithm);
		this.modulus = modulus;
		this.exponent = exponent;
	}

	/**
	 * @return the modulus value for the Public Key
	 */
	String getModulus() {
		return this.modulus;
	}

	/**
	 * @return the exponent value for the Public Key
	 */
	String getExponent() {
		return this.exponent;
	}
}