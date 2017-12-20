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
 * A JSON Web Key (JWK) representation of an Elliptic Curve key.
 *
 * @author Michael Duergner <michael@sprucehill.io>
 * @since 2.3
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7517">JSON Web Key (JWK)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7518#page-28">JSON Web Algorithms (JWA)</a>
 */
final class EllipticCurveJwkDefinition extends JwkDefinition {
	private final String x;
	private final String y;
	private final String curve;

	/**
	 * Creates an instance of an Elliptic Curve JSON Web Key (JWK).
	 *
	 * @param keyId        the Key ID
	 * @param publicKeyUse the intended use of the Public Key
	 * @param algorithm    the algorithm intended to be used
	 * @param x            the x value to be used
	 * @param y            the y value to be used
	 * @param curve        the curve to be used
	 */
	EllipticCurveJwkDefinition(String keyId,
							   PublicKeyUse publicKeyUse,
							   CryptoAlgorithm algorithm,
							   String x,
							   String y,
							   String curve) {
		super(keyId, KeyType.EC, publicKeyUse, algorithm);
		this.x = x;
		this.y = y;
		this.curve = curve;
	}

	String getX() {
		return this.x;
	}

	String getY() {
		return this.y;
	}

	String getCurve() {
		return this.curve;
	}

	/**
	 * The supported Named Curves.
	 */
	enum NamedCurve {
		P256("P-256"),
		P384("P-384"),
		P521("P-521");

		private final String value;

		NamedCurve(String value) {
			this.value = value;
		}

		String value() {
			return this.value;
		}

		static EllipticCurveJwkDefinition.NamedCurve fromValue(String curveName) {
			EllipticCurveJwkDefinition.NamedCurve result = null;
			for (EllipticCurveJwkDefinition.NamedCurve namedCurve : values()) {
				if (namedCurve.value().equals(curveName)) {
					result = namedCurve;
					break;
				}
			}
			return result;
		}
	}
}
