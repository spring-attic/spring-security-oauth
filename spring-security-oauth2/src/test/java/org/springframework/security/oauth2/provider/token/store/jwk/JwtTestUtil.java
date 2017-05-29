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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.jwt.codec.Codecs;

import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Joe Grandja
 */
class JwtTestUtil {
	private static final ObjectMapper objectMapper = new ObjectMapper();

	static String createJwt() throws Exception {
		return createJwt(createDefaultJwtHeader());
	}

	static String createJwt(byte[] jwtHeader) throws Exception {
		return createJwt(jwtHeader, createDefaultJwtPayload());
	}

	static String createJwt(byte[] jwtHeader, byte[] jwtPayload) throws Exception {
		byte[] encodedJwtHeader = Codecs.b64UrlEncode(jwtHeader);
		byte[] encodedJwtPayload = Codecs.b64UrlEncode(jwtPayload);
		byte[] period = Codecs.utf8Encode(".");
		return new String(join(encodedJwtHeader, period, encodedJwtPayload));
	}

	static byte[] createDefaultJwtHeader() throws Exception {
		return createJwtHeader("key-id-1", JwkDefinition.CryptoAlgorithm.RS256);
	}

	static byte[] createJwtHeader(String keyId, JwkDefinition.CryptoAlgorithm algorithm) throws Exception {
		Map<String, Object> jwtHeader = new HashMap<String, Object>();
		if (keyId != null) {
			jwtHeader.put(JwkAttributes.KEY_ID, keyId);
		}
		if (algorithm != null) {
			jwtHeader.put(JwkAttributes.ALGORITHM, algorithm.headerParamValue());
		}
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		objectMapper.writeValue(out, jwtHeader);
		return out.toByteArray();
	}

	static byte[] createDefaultJwtPayload() throws Exception {
		Map<String, Object> jwtPayload = new HashMap<String, Object>();
		jwtPayload.put("claim-name-1", "claim-value-1");
		jwtPayload.put("claim-name-2", "claim-value-2");
		jwtPayload.put("claim-name-3", "claim-value-3");
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		objectMapper.writeValue(out, jwtPayload);
		return out.toByteArray();
	}

	private static byte[] join(byte[]... byteArrays) {
		int size = 0;
		for (byte[] bytes : byteArrays) {
			size += bytes.length;
		}
		byte[] result = new byte[size];
		int index = 0;
		for (byte[] bytes : byteArrays) {
			System.arraycopy(bytes, 0, result, index, bytes.length);
			index += bytes.length;
		}
		return result;
	}
}