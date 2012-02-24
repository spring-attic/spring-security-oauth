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

import java.security.GeneralSecurityException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Luke Taylor
 */
public class MacSigner implements SignerVerifier {
	private static final String DEFAULT_ALGORITHM = "HMACSHA256";

	private final String algorithm;
	private final SecretKey key;

	public MacSigner(byte[] key) {
		this(new SecretKeySpec(key, DEFAULT_ALGORITHM));
	}

	public MacSigner(String key) {
		this(new SecretKeySpec(key.getBytes(), DEFAULT_ALGORITHM));
	}

	public MacSigner(SecretKey key) {
		this(DEFAULT_ALGORITHM, key);
	}

	public MacSigner(String algorithm, SecretKey key) {
		this.key = key;
		this.algorithm = algorithm;
	}

//	val keyLength = key.getEncoded.length * 8

	public byte[] sign(byte[] bytes) {
		try {
			Mac mac = Mac.getInstance(algorithm);
			mac.init(key);
			return mac.doFinal(bytes);
		}
		catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}

  public void verify(byte[] content, byte[] signature) {
    byte[] signed = sign(content);
    if (!isEqual(signed, signature)) {
      throw new InvalidSignatureException("Calculated signature did not match actual value");
    }
  }

  private boolean isEqual(byte[] b1, byte[] b2) {
    if (b1.length != b2.length) {
      return false;
    }
    int xor = 0;
    for (int i = 0; i < b1.length; i++) {
      xor |= b1[i] ^ b2[i];
    }

    return xor == 0;
  }

	public String algorithm() {
		return algorithm;
	}

	@Override
	public String toString() {
		return "MacSigner: " + algorithm;
	}
}
