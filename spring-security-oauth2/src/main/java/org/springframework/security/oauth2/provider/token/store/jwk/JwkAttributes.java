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
final class JwkAttributes {
	static final String KEY_ID = "kid";

	static final String KEY_TYPE = "kty";

	static final String ALGORITHM = "alg";

	static final String PUBLIC_KEY_USE = "use";

	static final String RSA_PUBLIC_KEY_MODULUS = "n";

	static final String RSA_PUBLIC_KEY_EXPONENT = "e";

	static final String KEYS = "keys";
}