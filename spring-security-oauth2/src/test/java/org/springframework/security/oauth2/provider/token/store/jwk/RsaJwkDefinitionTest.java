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
public class RsaJwkDefinitionTest {

	@Test
	public void constructorWhenArgumentsPassedThenAttributesAreCorrectlySet() throws Exception {
		String keyId = "key-id-1";
		JwkDefinition.PublicKeyUse publicKeyUse = JwkDefinition.PublicKeyUse.ENC;
		JwkDefinition.CryptoAlgorithm algorithm = JwkDefinition.CryptoAlgorithm.RS384;
		String modulus = "AMh-pGAj9vX2gwFDyrXot1f2YfHgh8h0Qx6w9IqLL";
		String exponent = "AQAB";

		RsaJwkDefinition rsaJwkDefinition = new RsaJwkDefinition(
				keyId, publicKeyUse, algorithm, modulus, exponent);

		assertEquals(keyId, rsaJwkDefinition.getKeyId());
		assertEquals(JwkDefinition.KeyType.RSA, rsaJwkDefinition.getKeyType());
		assertEquals(publicKeyUse, rsaJwkDefinition.getPublicKeyUse());
		assertEquals(algorithm, rsaJwkDefinition.getAlgorithm());
		assertEquals(modulus, rsaJwkDefinition.getModulus());
		assertEquals(exponent, rsaJwkDefinition.getExponent());
	}
}