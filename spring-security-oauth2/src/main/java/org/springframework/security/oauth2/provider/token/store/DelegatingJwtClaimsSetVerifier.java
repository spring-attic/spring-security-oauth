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
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * A {@link JwtClaimsSetVerifier} that delegates claims verification
 * to it's internal <code>List</code> of {@link JwtClaimsSetVerifier}'s.
 *
 * @author Joe Grandja
 * @since 2.2
 * @see JwtClaimsSetVerifier
 */
public class DelegatingJwtClaimsSetVerifier implements JwtClaimsSetVerifier {
	private final List<JwtClaimsSetVerifier> jwtClaimsSetVerifiers;

	public DelegatingJwtClaimsSetVerifier(List<JwtClaimsSetVerifier> jwtClaimsSetVerifiers) {
		Assert.notEmpty(jwtClaimsSetVerifiers, "jwtClaimsSetVerifiers cannot be empty");
		this.jwtClaimsSetVerifiers = Collections.unmodifiableList(new ArrayList<JwtClaimsSetVerifier>(jwtClaimsSetVerifiers));
	}

	@Override
	public void verify(Map<String, Object> claims) throws InvalidTokenException {
		for (JwtClaimsSetVerifier jwtClaimsSetVerifier : this.jwtClaimsSetVerifiers) {
			jwtClaimsSetVerifier.verify(claims);
		}
	}
}