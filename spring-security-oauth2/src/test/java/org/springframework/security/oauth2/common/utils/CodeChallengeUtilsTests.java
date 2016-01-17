/*
 * Copyright 2006-2011 the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.oauth2.common.utils;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.springframework.security.oauth2.common.util.CodeChallengeUtils;

/**
 * @author Marco Lenzo
 */
public class CodeChallengeUtilsTests {

	@Test
	public void testPlainCodeChallenge() {
		String codeVerifier = "plainCodeChallenge";
		String codeChallenge = CodeChallengeUtils.getCodeChallenge("plainCodeChallenge", "plain");
		assertEquals(codeChallenge, codeVerifier);
	}

	@Test
	public void testS256CodeChallenge() {
		// As per example RFC7636 Appendix B example:
		// Code verifier is dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
		// Code challenge is E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
		String codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
		String codeChallenge = CodeChallengeUtils.getCodeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
				"S256");
		assertEquals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", codeChallenge);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testCodeChallengeWithUnsupportedCodeChallengeMethod() {
		CodeChallengeUtils.getCodeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "xyz");
	}

}
