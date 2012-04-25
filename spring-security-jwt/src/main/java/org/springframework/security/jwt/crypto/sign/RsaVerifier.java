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

import static org.springframework.security.jwt.codec.Codecs.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;

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
		this(createPublicKey(n, e));
	}

	public RsaVerifier(RSAPublicKey key) {
		this(key, RsaSigner.DEFAULT_ALGORITHM);
	}

	public RsaVerifier(RSAPublicKey key, String algorithm) {
		this.key = key;
		this.algorithm = algorithm;
	}

	public RsaVerifier(String key) {
		this(parsePublicKey(key.trim()), RsaSigner.DEFAULT_ALGORITHM);
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

	private static RSAPublicKey createPublicKey(BigInteger n, BigInteger e) {
		try {
			return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
		}
		catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}

	private static final Pattern SSH_PUB_KEY = Pattern.compile("ssh-(rsa|dsa) ([A-Za-z0-9/+=]+) (.*)");

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private static RSAPublicKey parsePublicKey(String key) {
		Matcher m = SSH_PUB_KEY.matcher(key);

		if (m.matches()) {
			String alg = m.group(1);
			String encKey = m.group(2);
			//String id = m.group(3);

			if (!"rsa".equalsIgnoreCase(alg)) {
				throw new IllegalArgumentException("Only RSA is currently supported, but algorithm was " + alg);
			}

			return parseSSHPublicKey(encKey);
		} else if (!key.startsWith("-----BEGIN")) {
			// Assume it's the plain Base64 encoded ssh key without the "ssh-rsa" at the start
			return parseSSHPublicKey(key);
		}

		PEMReader pemReader = new PEMReader(new StringReader(key));

		try {
			KeyPair kp = (KeyPair) pemReader.readObject();

			if (kp == null) {
				throw new IllegalArgumentException("Not a valid PEM encoded key");
			}

			return (RSAPublicKey) kp.getPublic();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

	}

	private static RSAPublicKey parseSSHPublicKey(String encKey) {
		final byte[] PREFIX = new byte[] {0,0,0,7, 's','s','h','-','r','s','a'};
		ByteArrayInputStream in = new ByteArrayInputStream(b64Decode(utf8Encode(encKey)));

		byte[] prefix = new byte[11];

		try {
			if (in.read(prefix) != 11 || !Arrays.equals(PREFIX, prefix)) {
				throw new IllegalArgumentException("SSH key prefix not found");
			}

			BigInteger e = new BigInteger(readBigInteger(in));
			BigInteger n = new BigInteger(readBigInteger(in));

			return createPublicKey(n, e);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private static byte[] readBigInteger(ByteArrayInputStream in) throws IOException {
		byte[] b = new byte[4];

		if (in.read(b) != 4) {
			throw new IOException("Expected length data as 4 bytes");
		}

		int l = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];

		b = new byte[l];

		if (in.read(b) != l) {
			throw new IOException("Expected " + l + " key bytes");
		}

		return b;
	}
}
