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

import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * @author Joe Grandja
 */
public class JwkDefinitionTest {

	@Test
	public void constructorWhenArgumentsPassedThenAttributesAreCorrectlySet() throws Exception {
		String keyId = "key-id-1";
		JwkDefinition.KeyType keyType = JwkDefinition.KeyType.RSA;
		JwkDefinition.PublicKeyUse publicKeyUse = JwkDefinition.PublicKeyUse.SIG;
		JwkDefinition.CryptoAlgorithm algorithm = JwkDefinition.CryptoAlgorithm.RS512;

		JwkDefinition jwkDefinition = new JwkDefinition(keyId, keyType, publicKeyUse, algorithm) { };

		assertEquals(keyId, jwkDefinition.getKeyId());
		assertEquals(keyType, jwkDefinition.getKeyType());
		assertEquals(publicKeyUse, jwkDefinition.getPublicKeyUse());
		assertEquals(algorithm, jwkDefinition.getAlgorithm());
	}

	@Test
	public void cryptoAlgorithmWhenAttributesAccessedThenCorrectValuesReturned() {
		assertEquals("RS256", JwkDefinition.CryptoAlgorithm.RS256.headerParamValue());
		assertEquals("SHA256withRSA", JwkDefinition.CryptoAlgorithm.RS256.standardName());
		assertEquals("RS384", JwkDefinition.CryptoAlgorithm.RS384.headerParamValue());
		assertEquals("SHA384withRSA", JwkDefinition.CryptoAlgorithm.RS384.standardName());
		assertEquals("RS512", JwkDefinition.CryptoAlgorithm.RS512.headerParamValue());
		assertEquals("SHA512withRSA", JwkDefinition.CryptoAlgorithm.RS512.standardName());
	}
}