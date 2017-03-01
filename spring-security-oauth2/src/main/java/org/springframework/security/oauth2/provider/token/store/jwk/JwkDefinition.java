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
 * The base representation of a JSON Web Key (JWK).
 *
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7517">JSON Web Key (JWK)</a>
 *
 * @author Joe Grandja
 */
abstract class JwkDefinition {
	private final String keyId;
	private final KeyType keyType;
	private final PublicKeyUse publicKeyUse;
	private final CryptoAlgorithm algorithm;

	/**
	 * Creates an instance with the common attributes of a JWK.
	 *
	 * @param keyId the Key ID
	 * @param keyType the Key Type
	 * @param publicKeyUse the intended use of the Public Key
	 * @param algorithm the algorithm intended to be used
	 */
	protected JwkDefinition(String keyId,
							KeyType keyType,
							PublicKeyUse publicKeyUse,
							CryptoAlgorithm algorithm) {
		this.keyId = keyId;
		this.keyType = keyType;
		this.publicKeyUse = publicKeyUse;
		this.algorithm = algorithm;
	}

	/**
	 * @return the Key ID (&quot;kid&quot;)
	 */
	String getKeyId() {
		return this.keyId;
	}

	/**
	 * @return the Key Type (&quot;kty&quot;)
	 */
	KeyType getKeyType() {
		return this.keyType;
	}

	/**
	 * @return the intended use of the Public Key (&quot;use&quot;)
	 */
	PublicKeyUse getPublicKeyUse() {
		return this.publicKeyUse;
	}

	/**
	 *
	 * @return the algorithm intended to be used (&quot;alg&quot;)
	 */
	CryptoAlgorithm getAlgorithm() {
		return this.algorithm;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || this.getClass() != obj.getClass()) {
			return false;
		}

		JwkDefinition that = (JwkDefinition) obj;
		if (!this.getKeyId().equals(that.getKeyId())) {
			return false;
		}

		return this.getKeyType().equals(that.getKeyType());
	}

	@Override
	public int hashCode() {
		int result = this.getKeyId().hashCode();
		result = 31 * result + this.getKeyType().hashCode();
		return result;
	}

	/**
	 * The defined Key Type (&quot;kty&quot;) values.
	 */
	enum KeyType {
		RSA("RSA"),
		EC("EC"),
		OCT("oct");

		private final String value;

		KeyType(String value) {
			this.value = value;
		}

		String value() {
			return this.value;
		}

		static KeyType fromValue(String value) {
			KeyType result = null;
			for (KeyType keyType : values()) {
				if (keyType.value().equals(value)) {
					result = keyType;
					break;
				}
			}
			return result;
		}
	}

	/**
	 * The defined Public Key Use (&quot;use&quot;) values.
	 */
	enum PublicKeyUse {
		SIG("sig"),
		ENC("enc");

		private final String value;

		PublicKeyUse(String value) {
			this.value = value;
		}

		String value() {
			return this.value;
		}

		static PublicKeyUse fromValue(String value) {
			PublicKeyUse result = null;
			for (PublicKeyUse publicKeyUse : values()) {
				if (publicKeyUse.value().equals(value)) {
					result = publicKeyUse;
					break;
				}
			}
			return result;
		}
	}

	/**
	 * The defined Algorithm (&quot;alg&quot;) values.
	 */
	enum CryptoAlgorithm {
		RS256("SHA256withRSA", "RS256"),
		RS384("SHA384withRSA", "RS384"),
		RS512("SHA512withRSA", "RS512");

		private final String standardName;		// JCA Standard Name
		private final String headerParamValue;

		CryptoAlgorithm(String standardName, String headerParamValue) {
			this.standardName = standardName;
			this.headerParamValue = headerParamValue;
		}

		String standardName() {
			return this.standardName;
		}

		String headerParamValue() {
			return this.headerParamValue;
		}

		static CryptoAlgorithm fromHeaderParamValue(String headerParamValue) {
			CryptoAlgorithm result = null;
			for (CryptoAlgorithm algorithm : values()) {
				if (algorithm.headerParamValue().equals(headerParamValue)) {
					result = algorithm;
					break;
				}
			}
			return result;
		}
	}
}