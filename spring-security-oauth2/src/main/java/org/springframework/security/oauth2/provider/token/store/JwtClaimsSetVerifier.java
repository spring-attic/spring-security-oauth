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
package org.springframework.security.oauth2.provider.token.store;

import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;

import java.util.Map;

/**
 * This interface provides the capability of verifying the claim(s)
 * contained in a JWT Claims Set, for example, expiration time (exp),
 * not before (nbf), issuer (iss), audience (aud), subject (sub), etc.
 *
 * @author Joe Grandja
 * @since 2.2
 * @see JwtAccessTokenConverter
 */
public interface JwtClaimsSetVerifier {

	/**
	 * Verify the claim(s) in the JWT Claims Set.
	 *
	 * @param claims the JWT Claims Set
	 * @throws InvalidTokenException if at least one claim failed verification
	 */
	void verify(Map<String, Object> claims) throws InvalidTokenException;

}