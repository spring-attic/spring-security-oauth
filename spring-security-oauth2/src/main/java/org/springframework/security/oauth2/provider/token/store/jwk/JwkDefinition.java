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

/**
 * @author Joe Grandja
 */
abstract class JwkDefinition {
	private final String keyId;
	private final KeyType keyType;
	private final PublicKeyUse publicKeyUse;
	private final CryptoAlgorithm algorithm;

	protected JwkDefinition(String keyId,
							KeyType keyType,
							PublicKeyUse publicKeyUse,
							CryptoAlgorithm algorithm) {
		this.keyId = keyId;
		this.keyType = keyType;
		this.publicKeyUse = publicKeyUse;
		this.algorithm = algorithm;
	}

	String getKeyId() {
		return this.keyId;
	}

	KeyType getKeyType() {
		return this.keyType;
	}

	PublicKeyUse getPublicKeyUse() {
		return this.publicKeyUse;
	}

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

	enum CryptoAlgorithm {
		RS256("SHA256withRSA", "RS256", "RSASSA-PKCS1-v1_5 using SHA-256"),
		RS384("SHA384withRSA", "RS384", "RSASSA-PKCS1-v1_5 using SHA-384"),
		RS512("SHA512withRSA", "RS512", "RSASSA-PKCS1-v1_5 using SHA-512");

		private final String standardName;		// JCA Standard Name
		private final String headerParamValue;
		private final String description;

		CryptoAlgorithm(String standardName, String headerParamValue, String description) {
			this.standardName = standardName;
			this.headerParamValue = headerParamValue;
			this.description = description;
		}

		String standardName() {
			return this.standardName;
		}

		String headerParamValue() {
			return this.headerParamValue;
		}

		String description() {
			return this.description;
		}

		static CryptoAlgorithm fromStandardName(String standardName) {
			CryptoAlgorithm result = null;
			for (CryptoAlgorithm algorithm : values()) {
				if (algorithm.standardName().equals(standardName)) {
					result = algorithm;
					break;
				}
			}
			return result;
		}
	}
}