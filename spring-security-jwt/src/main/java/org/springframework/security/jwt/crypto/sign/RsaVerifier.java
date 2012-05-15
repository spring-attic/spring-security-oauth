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

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;

/**
 * Verifies signatures using an RSA public key.
 *
 * The key can be supplied directly, or as an SSH public or private key string (in
 * the standard format produced by <tt>ssh-keygen</tt>).
 *
 * @author Luke Taylor
 */
public class RsaVerifier implements SignatureVerifier {
	private final RSAPublicKey key;
	private final String algorithm;

	public RsaVerifier(BigInteger n, BigInteger e) {
		this(RsaKeyHelper.createPublicKey(n, e));
	}

	public RsaVerifier(RSAPublicKey key) {
		this(key, RsaSigner.DEFAULT_ALGORITHM);
	}

	public RsaVerifier(RSAPublicKey key, String algorithm) {
		this.key = key;
		this.algorithm = algorithm;
	}

	public RsaVerifier(String key) {
		this(RsaKeyHelper.parsePublicKey(key.trim()), RsaSigner.DEFAULT_ALGORITHM);
	}

	public void verify(byte[] content, byte[] sig) {
		try {
			Signature signature = Signature.getInstance(algorithm);
			signature.initVerify(key);
			signature.update(content);

			if (!signature.verify(sig)) {
				throw new InvalidSignatureException("RSA Signature did not match content");
			}
		}
		catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}

	public String algorithm() {
		return algorithm;
	}
}
