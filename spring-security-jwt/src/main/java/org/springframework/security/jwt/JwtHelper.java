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

import static org.springframework.security.jwt.JwtAlgorithms.sigAlg;
import static org.springframework.security.jwt.codec.Codecs.b64UrlDecode;
import static org.springframework.security.jwt.codec.Codecs.b64UrlEncode;
import static org.springframework.security.jwt.codec.Codecs.concat;
import static org.springframework.security.jwt.codec.Codecs.utf8Decode;
import static org.springframework.security.jwt.codec.Codecs.utf8Encode;

import java.nio.CharBuffer;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.jwt.crypto.sign.Signer;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
public class JwtHelper {
	static byte[] PERIOD = utf8Encode(".");

	/**
	 * Creates a token from an encoded token string.
	 *
	 * @param token the (non-null) encoded token (three Base-64 encoded strings separated
	 * by "." characters)
	 */
	public static Jwt decode(String token) {
		int firstPeriod = token.indexOf('.');
		int lastPeriod = token.lastIndexOf('.');

		if (firstPeriod <= 0 || lastPeriod <= firstPeriod) {
			throw new IllegalArgumentException("JWT must have 3 tokens");
		}
		CharBuffer buffer = CharBuffer.wrap(token, 0, firstPeriod);
		// TODO: Use a Reader which supports CharBuffer
		JwtHeader header = JwtHeaderHelper.create(buffer.toString());

		buffer.limit(lastPeriod).position(firstPeriod + 1);
		byte[] claims = b64UrlDecode(buffer);
		boolean emptyCrypto = lastPeriod == token.length() - 1;

		byte[] crypto;

		if (emptyCrypto) {
			if (!"none".equals(header.parameters.alg)) {
				throw new IllegalArgumentException(
						"Signed or encrypted token must have non-empty crypto segment");
			}
			crypto = new byte[0];
		}
		else {
			buffer.limit(token.length()).position(lastPeriod + 1);
			crypto = b64UrlDecode(buffer);
		}
		return new JwtImpl(header, claims, crypto);
	}

	public static Jwt decodeAndVerify(String token, SignatureVerifier verifier) {
		Jwt jwt = decode(token);
		jwt.verifySignature(verifier);

		return jwt;
	}
	
	public static Map<String, String> headers(String token) {
		JwtImpl jwt = (JwtImpl) decode(token);
		Map<String, String> map = new LinkedHashMap<String, String>(jwt.header.parameters.map);
		map.put("alg", jwt.header.parameters.alg);
		if (jwt.header.parameters.typ!=null) {
			map.put("typ", jwt.header.parameters.typ);
		}
		return map;
	}

	public static Jwt encode(CharSequence content, Signer signer) {
		return encode(content, signer, Collections.<String, String>emptyMap());
	}

	public static Jwt encode(CharSequence content, Signer signer,
			Map<String, String> headers) {
		JwtHeader header = JwtHeaderHelper.create(signer, headers);
		byte[] claims = utf8Encode(content);
		byte[] crypto = signer
				.sign(concat(b64UrlEncode(header.bytes()), PERIOD, b64UrlEncode(claims)));
		return new JwtImpl(header, claims, crypto);
	}
}

/**
 * Helper object for JwtHeader.
 *
 * Handles the JSON parsing and serialization.
 */
class JwtHeaderHelper {

	static JwtHeader create(String header) {
		byte[] bytes = b64UrlDecode(header);
		return new JwtHeader(bytes, parseParams(bytes));
	}

	static JwtHeader create(Signer signer, Map<String, String> params) {
		Map<String, String> map = new LinkedHashMap<String, String>(params);
		map.put("alg", sigAlg(signer.algorithm()));
		HeaderParameters p = new HeaderParameters(map);
		return new JwtHeader(serializeParams(p), p);
	}

	static HeaderParameters parseParams(byte[] header) {
		Map<String, String> map = parseMap(utf8Decode(header));
		return new HeaderParameters(map);
	}

	private static Map<String, String> parseMap(String json) {
		if (json != null) {
			json = json.trim();
			if (json.startsWith("{")) {
				return parseMapInternal(json);
			}
			else if (json.equals("")) {
				return new LinkedHashMap<String, String>();
			}
		}
		throw new IllegalArgumentException("Invalid JSON (null)");
	}

	private static Map<String, String> parseMapInternal(String json) {
		Map<String, String> map = new LinkedHashMap<String, String>();
		json = trimLeadingCharacter(trimTrailingCharacter(json, '}'), '{');
		for (String pair : json.split(",")) {
			String[] values = pair.split(":");
			String key = strip(values[0], '"');
			String value = null;
			if (values.length > 0) {
				value = strip(values[1], '"');
			}
			if (map.containsKey(key)) {
				throw new IllegalArgumentException("Duplicate '" + key + "' field");
			}
			map.put(key, value);
		}
		return map;
	}

	private static String strip(String string, char c) {
		return trimLeadingCharacter(trimTrailingCharacter(string.trim(), c), c);
	}

	private static String trimTrailingCharacter(String string, char c) {
		if (string.length() >= 0 && string.charAt(string.length() - 1) == c) {
			return string.substring(0, string.length() - 1);
		}
		return string;
	}

	private static String trimLeadingCharacter(String string, char c) {
		if (string.length() >= 0 && string.charAt(0) == c) {
			return string.substring(1);
		}
		return string;
	}

	private static byte[] serializeParams(HeaderParameters params) {
		StringBuilder builder = new StringBuilder("{");

		appendField(builder, "alg", params.alg);
		if (params.typ != null) {
			appendField(builder, "typ", params.typ);
		}
		for (Entry<String, String> entry : params.map.entrySet()) {
			appendField(builder, entry.getKey(), entry.getValue());
		}
		builder.append("}");
		return utf8Encode(builder.toString());

	}

	private static void appendField(StringBuilder builder, String name, String value) {
		if (builder.length() > 1) {
			builder.append(",");
		}
		builder.append("\"").append(name).append("\":\"").append(value).append("\"");
	}
}

/**
 * Header part of JWT
 *
 */
class JwtHeader implements BinaryFormat {
	private final byte[] bytes;

	final HeaderParameters parameters;

	/**
	 * @param bytes the decoded header
	 * @param parameters the parameter values contained in the header
	 */
	JwtHeader(byte[] bytes, HeaderParameters parameters) {
		this.bytes = bytes;
		this.parameters = parameters;
	}

	@Override
	public byte[] bytes() {
		return bytes;
	}

	@Override
	public String toString() {
		return utf8Decode(bytes);
	}
}

class HeaderParameters {
	final String alg;

	final Map<String, String> map;

	final String typ = "JWT";

	HeaderParameters(String alg) {
		this(new LinkedHashMap<String, String>(Collections.singletonMap("alg", alg)));
	}

	HeaderParameters(Map<String, String> map) {
		String alg = map.get("alg"), typ = map.get("typ");
		if (typ != null && !"JWT".equalsIgnoreCase(typ)) {
			throw new IllegalArgumentException("typ is not \"JWT\"");
		}
		map.remove("alg");
		map.remove("typ");
		this.map = map;
		if (alg == null) {
			throw new IllegalArgumentException("alg is required");
		}
		this.alg = alg;
	}

}

class JwtImpl implements Jwt {
	final JwtHeader header;

	private final byte[] content;

	private final byte[] crypto;

	private String claims;

	/**
	 * @param header the header, containing the JWS/JWE algorithm information.
	 * @param content the base64-decoded "claims" segment (may be encrypted, depending on
	 * header information).
	 * @param crypto the base64-decoded "crypto" segment.
	 */
	JwtImpl(JwtHeader header, byte[] content, byte[] crypto) {
		this.header = header;
		this.content = content;
		this.crypto = crypto;
		claims = utf8Decode(content);
	}

	/**
	 * Validates a signature contained in the 'crypto' segment.
	 *
	 * @param verifier the signature verifier
	 */
	@Override
	public void verifySignature(SignatureVerifier verifier) {
		verifier.verify(signingInput(), crypto);
	}

	private byte[] signingInput() {
		return concat(b64UrlEncode(header.bytes()), JwtHelper.PERIOD,
				b64UrlEncode(content));
	}

	/**
	 * Allows retrieval of the full token.
	 *
	 * @return the encoded header, claims and crypto segments concatenated with "."
	 * characters
	 */
	@Override
	public byte[] bytes() {
		return concat(b64UrlEncode(header.bytes()), JwtHelper.PERIOD,
				b64UrlEncode(content), JwtHelper.PERIOD, b64UrlEncode(crypto));
	}

	@Override
	public String getClaims() {
		return utf8Decode(content);
	}

	@Override
	public String getEncoded() {
		return utf8Decode(bytes());
	}
	
	public JwtHeader header() {
		return this.header;
	}

	@Override
	public String toString() {
		return header + " " + claims + " [" + crypto.length + " crypto bytes]";
	}
}
