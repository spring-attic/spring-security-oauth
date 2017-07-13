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
import org.springframework.util.CollectionUtils;

import java.net.URL;
import java.util.Map;

/**
 * A {@link JwtClaimsSetVerifier} that verifies the Issuer (iss) claim contained in the
 * JWT Claims Set against the <code>issuer</code> supplied to the constructor.
 *
 * @author Joe Grandja
 * @since 2.2
 * @see JwtClaimsSetVerifier
 */
public class IssuerClaimVerifier implements JwtClaimsSetVerifier {
	private static final String ISS_CLAIM = "iss";
	private final URL issuer;

	public IssuerClaimVerifier(URL issuer) {
		Assert.notNull(issuer, "issuer cannot be null");
		this.issuer = issuer;
	}

	@Override
	public void verify(Map<String, Object> claims) throws InvalidTokenException {
		if (!CollectionUtils.isEmpty(claims) && claims.containsKey(ISS_CLAIM)) {
			String jwtIssuer = (String)claims.get(ISS_CLAIM);
			if (!jwtIssuer.equals(this.issuer.toString())) {
				throw new InvalidTokenException("Invalid Issuer (iss) claim: " + jwtIssuer);
			}
		}
	}
}