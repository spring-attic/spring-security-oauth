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
 * Shared attribute values used by {@link JwkTokenStore} and associated collaborators.
 *
 * @author Joe Grandja
 */
final class JwkAttributes {

	/**
	 * The &quot;kid&quot; (key ID) parameter used in a JWT header and in a JWK.
	 */
	static final String KEY_ID = "kid";

	/**
	 * The &quot;kty&quot; (key type) parameter identifies the cryptographic algorithm family
	 * used by a JWK, for example, &quot;RSA&quot; or &quot;EC&quot;.
	 */
	static final String KEY_TYPE = "kty";

	/**
	 * The &quot;alg&quot; (algorithm) parameter used in a JWT header and in a JWK.
	 */
	static final String ALGORITHM = "alg";

	/**
	 * The &quot;use&quot; (public key use) parameter identifies the intended use of the public key.
	 * For example, whether a public key is used for encrypting data or verifying the signature on data.
	 */
	static final String PUBLIC_KEY_USE = "use";

	/**
	 * The &quot;n&quot; (modulus) parameter contains the modulus value for a RSA public key.
	 */
	static final String RSA_PUBLIC_KEY_MODULUS = "n";

	/**
	 * The &quot;e&quot; (exponent) parameter contains the exponent value for a RSA public key.
	 */
	static final String RSA_PUBLIC_KEY_EXPONENT = "e";

	/**
	 * A JWK Set is a JSON object that has a &quot;keys&quot; member
	 * and its value is an array (set) of JWKs.
	 */
	static final String KEYS = "keys";
}