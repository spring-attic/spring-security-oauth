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
package org.springframework.security.jwt;

import java.math.BigInteger;

import org.springframework.security.jwt.crypto.cipher.RsaTestKeyData;

/**
 * @author Luke Taylor
 */
public class JwtSpecData {
	final static byte[] HMAC_KEY;

	static {
		int[] keyInts = new int[] {3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166, 143, 90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80, 46, 191, 211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195, 119, 98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245, 103, 208, 128, 163};
		HMAC_KEY = new byte[keyInts.length];

		for (int i=0; i < keyInts.length; i++) {
			HMAC_KEY[i] = (byte)keyInts[i];
		}
	}

	// RSA Key parts
	static final BigInteger N = RsaTestKeyData.N;
	static final BigInteger E = RsaTestKeyData.E;
	static final BigInteger D = RsaTestKeyData.D;
}
