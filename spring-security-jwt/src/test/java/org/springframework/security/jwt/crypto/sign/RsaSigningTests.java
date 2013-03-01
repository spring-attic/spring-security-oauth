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
package org.springframework.security.jwt.crypto.sign;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;
import org.springframework.security.jwt.codec.Codecs;
import org.springframework.security.jwt.crypto.cipher.RsaTestKeyData;

/**
 * @author Luke Taylor
 */
public class RsaSigningTests {

	@Test(expected = IllegalArgumentException.class)
	public void rsaSignerRejectsInvalidKey() throws Exception {
		RsaSigner signer = new RsaSigner(RsaTestKeyData.SSH_PUBLIC_KEY_STRING);
		assertNotNull(signer);
	}

	@Test
	public void rsaSignerValidKeyWithWhitespace() throws Exception {
		RsaSigner signer = new RsaSigner(RsaTestKeyData.SSH_PRIVATE_KEY_STRING_WITH_WHITESPACE);
		assertNotNull(signer);
	}

	@Test
	public void keysFromPrivateAndPublicKeyStringDataAreCorrect() throws Exception {
		// Do a test sign and verify
		byte[] content = Codecs.utf8Encode("Hi I'm the data");

		RsaSigner signer = new RsaSigner(RsaTestKeyData.SSH_PRIVATE_KEY_STRING);
		final byte[] signed = signer.sign(content);
		// First extract the public key from the private key data
		RsaVerifier verifier = new RsaVerifier(RsaTestKeyData.SSH_PRIVATE_KEY_STRING);
		verifier.verify(content, signed);

		// Then try with the ssh-rsa public key format
		verifier = new RsaVerifier(RsaTestKeyData.SSH_PUBLIC_KEY_STRING);
		verifier.verify(content, signed);

		// Try with the PEM format public keys
		verifier = new RsaVerifier(RsaTestKeyData.SSH_PUBLIC_KEY_PEM_STRING);
		verifier.verify(content, signed);

		verifier = new RsaVerifier(RsaTestKeyData.SSH_PUBLIC_KEY_OPENSSL_PEM_STRING);
		verifier.verify(content, signed);
	}
}
