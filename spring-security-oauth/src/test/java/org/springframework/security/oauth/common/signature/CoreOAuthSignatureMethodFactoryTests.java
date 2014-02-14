/*
 * Copyright 2008 Web Cohesion
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth.common.signature;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;

import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;
import org.springframework.security.oauth.provider.token.OAuthProviderTokenImpl;

/**
 * @author Ryan Heaton
 */
public class CoreOAuthSignatureMethodFactoryTests {

	/**
	 * tests getting the signature method.
	 */
	@Test
	public void testGetSignatureMethod() throws Exception {
		CoreOAuthSignatureMethodFactory factory = new CoreOAuthSignatureMethodFactory();
		OAuthProviderTokenImpl token = new OAuthProviderTokenImpl();
		token.setSecret("token_SHHHHHHHHHHHHHH");
		SharedConsumerSecret sharedSecret = new SharedConsumerSecretImpl("consumer_shhhhhhhhhh");
		try {
			factory.getSignatureMethod("unknown", sharedSecret, token.getSecret());
			fail("should fail with unknown signature method.");
		} catch (UnsupportedSignatureMethodException e) {
			// fall thru...
		}

		try {
			factory.getSignatureMethod(PlainTextSignatureMethod.SIGNATURE_NAME, sharedSecret, token.getSecret());
			fail("plain text shouldn't be supported by default.");
		} catch (UnsupportedSignatureMethodException e) {
			// fall thru...
		}

		factory.setSupportPlainText(true);
		OAuthSignatureMethod signatureMethod = factory.getSignatureMethod(PlainTextSignatureMethod.SIGNATURE_NAME,
				sharedSecret, token.getSecret());
		assertTrue(signatureMethod instanceof PlainTextSignatureMethod);
		assertEquals("consumer_shhhhhhhhhh%26token_SHHHHHHHHHHHHHH",
				((PlainTextSignatureMethod) signatureMethod).getSecret());

		signatureMethod = factory.getSignatureMethod(HMAC_SHA1SignatureMethod.SIGNATURE_NAME, sharedSecret,
				token.getSecret());
		assertTrue(signatureMethod instanceof HMAC_SHA1SignatureMethod);
		SecretKeySpec spec = new SecretKeySpec("consumer_shhhhhhhhhh&token_SHHHHHHHHHHHHHH".getBytes("UTF-8"),
				HMAC_SHA1SignatureMethod.MAC_NAME);
		assertTrue(Arrays.equals(spec.getEncoded(), ((HMAC_SHA1SignatureMethod) signatureMethod).getSecretKey()
				.getEncoded()));

		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(1024);
		KeyPair keyPair = generator.generateKeyPair();
		signatureMethod = factory.getSignatureMethod(RSA_SHA1SignatureMethod.SIGNATURE_NAME,
				new RSAKeySecret(keyPair.getPrivate(), keyPair.getPublic()), token.getSecret());
		assertTrue(signatureMethod instanceof RSA_SHA1SignatureMethod);
		assertEquals(keyPair.getPrivate(), ((RSA_SHA1SignatureMethod) signatureMethod).getPrivateKey());
		assertEquals(keyPair.getPublic(), ((RSA_SHA1SignatureMethod) signatureMethod).getPublicKey());
	}

}
