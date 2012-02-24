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
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAPrivateKeySpec;

/**
 * A signer for signing using an RSA private key.
 *
 * @author Luke Taylor
 */
public class RsaSigner implements Signer {
	static final String DEFAULT_ALGORITHM = "SHA256withRSA";

	private final RSAPrivateKey key;
	private final String algorithm;

	public RsaSigner(BigInteger n, BigInteger d) {
		this(createPrivateKey(n,d));
	}

	public RsaSigner(RSAPrivateKey key) {
		this(key, DEFAULT_ALGORITHM);
	}

	public RsaSigner(RSAPrivateKey key, String algorithm) {
		this.key = key;
		this.algorithm = algorithm;
	}

	public byte[] sign(byte[] bytes) {
		try {
			Signature signature = Signature.getInstance(algorithm);
			signature.initSign(key);
			signature.update(bytes);
			return signature.sign();
		}
		catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}

	public String algorithm() {
		return algorithm;
	}

	private static RSAPrivateKey createPrivateKey(BigInteger n, BigInteger d) {
		try {
			return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateKeySpec(n, d));
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

}
