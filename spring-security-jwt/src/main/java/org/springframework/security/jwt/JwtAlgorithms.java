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

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.jwt.crypto.cipher.CipherMetadata;

/**
 * @author Luke Taylor
 */
public class JwtAlgorithms {
	private static final Map<String,String> sigAlgs = new HashMap<String,String>();
	private static final Map<String,String> javaToSigAlgs = new HashMap<String,String>();
	private static final Map<String,String> keyAlgs = new HashMap<String,String>();
	private static final Map<String,String> javaToKeyAlgs = new HashMap<String,String>();

	static {
		sigAlgs.put("HS256", "HMACSHA256");
		sigAlgs.put("HS384" , "HMACSHA384");
		sigAlgs.put("HS512" , "HMACSHA512");
		sigAlgs.put("RS256" , "SHA256withRSA");
		sigAlgs.put("RS512" , "SHA512withRSA");

		keyAlgs.put("RSA1_5" , "RSA/ECB/PKCS1Padding");

		for(Map.Entry<String,String> e: sigAlgs.entrySet()) {
			javaToSigAlgs.put(e.getValue(), e.getKey());
		}
		for(Map.Entry<String,String> e: keyAlgs.entrySet()) {
			javaToKeyAlgs.put(e.getValue(), e.getKey());
		}

	}

	static String sigAlg(String javaName){
		String alg = javaToSigAlgs.get(javaName);

		if (alg == null) {
			throw new IllegalArgumentException("Invalid or unsupported signature algorithm: " + javaName);
		}

		return alg;
	}

	static String keyEncryptionAlg(String javaName) {
		String alg = javaToKeyAlgs.get(javaName);

		if (alg == null) {
			throw new IllegalArgumentException("Invalid or unsupported key encryption algorithm: " + javaName);
		}

		return alg;
	}

	static String enc(CipherMetadata cipher) {
		if (!cipher.algorithm().equalsIgnoreCase("AES/CBC/PKCS5Padding")) {
			throw new IllegalArgumentException("Unknown or unsupported algorithm");
		}
		if (cipher.keySize() == 128) {
			return "A128CBC";
		} else if (cipher.keySize() == 256) {
			return "A256CBC";
		} else {
			throw new IllegalArgumentException("Unsupported key size");
		}
	}
}
