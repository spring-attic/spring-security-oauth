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

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Joe Grandja
 */
public class IssuerClaimVerifierTest {
	private static final String DEFAULT_ISSUER = "https://uaa.run.pivotal.io";
	private IssuerClaimVerifier issuerClaimVerifier;

	@Before
	public void setUp() throws Exception {
		this.issuerClaimVerifier = new IssuerClaimVerifier(new URL(DEFAULT_ISSUER));
	}

	@Test
	public void verifyWhenJwtClaimsSetContainsValidIssuerThenVerificationSucceeds() throws Exception {
		Map<String, Object> claims = new HashMap<String, Object>();
		claims.put("iss", DEFAULT_ISSUER);
		this.issuerClaimVerifier.verify(claims);
	}

	@Test(expected = InvalidTokenException.class)
	public void verifyWhenJwtClaimsSetContainsInvalidIssuerThenVerificationFails() throws Exception {
		Map<String, Object> claims = new HashMap<String, Object>();
		claims.put("iss", "https://invalid-uaa.run.pivotal.io");
		this.issuerClaimVerifier.verify(claims);
	}
}