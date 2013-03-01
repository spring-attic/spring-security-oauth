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

import static org.springframework.security.jwt.codec.Codecs.b64Decode;
import static org.springframework.security.jwt.codec.Codecs.utf8Encode;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1Sequence;

/**
 * Reads RSA key pairs using BC provider classes but without the
 * need to specify a crypto provider or have BC added as one.
 *
 * @author Luke Taylor
 */
class RsaKeyHelper {
	private static String BEGIN = "-----BEGIN";
	private static Pattern PEM_DATA = Pattern.compile("-----BEGIN (.*)-----(.*)-----END (.*)-----", Pattern.DOTALL);

	static KeyPair parseKeyPair(String pemData) {
		Matcher m = PEM_DATA.matcher(pemData.trim());

		if (!m.matches()) {
			throw new IllegalArgumentException("String is not PEM encoded data");
		}

		String type = m.group(1);
		final byte[] content = b64Decode(utf8Encode(m.group(2)));

		PublicKey publicKey;
		PrivateKey privateKey = null;

		try {
			KeyFactory fact = KeyFactory.getInstance("RSA");
			if (type.equals("RSA PRIVATE KEY")) {
				ASN1Sequence seq = ASN1Sequence.getInstance(content);
				if (seq.size() != 9) {
					throw new IllegalArgumentException("Invalid RSA Private Key ASN1 sequence.");
				}
				org.bouncycastle.asn1.pkcs.RSAPrivateKey key = org.bouncycastle.asn1.pkcs.RSAPrivateKey.getInstance(seq);
				RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(key.getModulus(), key.getPublicExponent());
				RSAPrivateCrtKeySpec privSpec = new RSAPrivateCrtKeySpec(key.getModulus(), key.getPublicExponent(),
					key.getPrivateExponent(), key.getPrime1(), key.getPrime2(), key.getExponent1(), key.getExponent2(),
					key.getCoefficient());
				publicKey = fact.generatePublic(pubSpec);
				privateKey = fact.generatePrivate(privSpec);
			} else if (type.equals("PUBLIC KEY")) {
				KeySpec keySpec = new X509EncodedKeySpec(content);
				publicKey = fact.generatePublic(keySpec);
			} else if (type.equals("RSA PUBLIC KEY")) {
				ASN1Sequence seq = ASN1Sequence.getInstance(content);
				org.bouncycastle.asn1.pkcs.RSAPublicKey key = org.bouncycastle.asn1.pkcs.RSAPublicKey.getInstance(seq);
				RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(key.getModulus(), key.getPublicExponent());
				publicKey = fact.generatePublic(pubSpec);
			} else {
				throw new IllegalArgumentException(type + " is not a supported format");
			}

			return new KeyPair(publicKey, privateKey);
		}
		catch (InvalidKeySpecException e) {
			throw new RuntimeException(e);
		}
		catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

	private static final Pattern SSH_PUB_KEY = Pattern.compile("ssh-(rsa|dsa) ([A-Za-z0-9/+]+=*) (.*)");

	static RSAPublicKey parsePublicKey(String key) {
		Matcher m = SSH_PUB_KEY.matcher(key);

		if (m.matches()) {
			String alg = m.group(1);
			String encKey = m.group(2);
			//String id = m.group(3);

			if (!"rsa".equalsIgnoreCase(alg)) {
				throw new IllegalArgumentException("Only RSA is currently supported, but algorithm was " + alg);
			}

			return parseSSHPublicKey(encKey);
		} else if (!key.startsWith(BEGIN)) {
			// Assume it's the plain Base64 encoded ssh key without the "ssh-rsa" at the start
			return parseSSHPublicKey(key);
		}

		KeyPair kp = parseKeyPair(key);

		if (kp.getPublic() == null) {
			throw new IllegalArgumentException("Key data does not contain a public key");
		}

		return (RSAPublicKey) kp.getPublic();
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

	static RSAPublicKey createPublicKey(BigInteger n, BigInteger e) {
		try {
			return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
		}
		catch (Exception ex) {
			throw new RuntimeException(ex);
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
