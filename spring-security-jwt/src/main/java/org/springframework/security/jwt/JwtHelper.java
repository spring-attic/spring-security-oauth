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
import java.util.LinkedHashMap;
import java.util.Map;

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
	 * @param token the (non-null) encoded token (three Base-64 encoded strings separated by "." characters)
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
				throw new IllegalArgumentException("Signed or encrypted token must have non-empty crypto segment");
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

	public static Jwt encode(CharSequence content, Signer signer) {
		JwtHeader header = JwtHeaderHelper.create(signer);
		byte[] claims = utf8Encode(content);
		byte[] crypto = signer.sign(concat(b64UrlEncode(header.bytes()), PERIOD, b64UrlEncode(claims)));
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

	static JwtHeader create(Signer signer) {
		HeaderParameters p = new HeaderParameters(sigAlg(signer.algorithm()), null, null);
		return new JwtHeader(serializeParams(p), p);
	}

	static JwtHeader create(String alg, String enc, byte[] iv) {
		HeaderParameters p = new HeaderParameters(alg, enc, utf8Decode(b64UrlEncode(iv)));
		return new JwtHeader(serializeParams(p), p);
	}

	static HeaderParameters parseParams(byte[] header) {
		Map<String, String> map = parseMap(utf8Decode(header));
		String alg = map.get("alg"), enc = map.get("enc"), iv = map.get("iv"), typ = map.get("typ");
		if (typ != null && !"JWT".equalsIgnoreCase(typ)) {
			throw new IllegalArgumentException("typ is not \"JWT\"");
		}
		return new HeaderParameters(alg, enc, iv);
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
		if (params.enc != null) {
			appendField(builder, "enc", params.enc);
		}
		if (params.iv != null) {
			appendField(builder, "iv", params.iv);
		}
		builder.append("}");
		return utf8Encode(builder.toString());

	}

	private static void appendField(StringBuilder builder, String name, String value) {
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

	final String enc;

	final String iv;

	HeaderParameters(String alg) {
		this(alg, null, null);
	}

	HeaderParameters(String alg, String enc, String iv) {
		if (alg == null) {
			throw new IllegalArgumentException("alg is required");
		}
		this.alg = alg;
		this.enc = enc;
		this.iv = iv;
	}

}

class JwtImpl implements Jwt {
	private final JwtHeader header;

	private final byte[] content;

	private final byte[] crypto;

	private String claims;

	/**
	 * @param header the header, containing the JWS/JWE algorithm information.
	 * @param content the base64-decoded "claims" segment (may be encrypted, depending on header information).
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
	public void verifySignature(SignatureVerifier verifier) {
		verifier.verify(signingInput(), crypto);
	}

	private byte[] signingInput() {
		return concat(b64UrlEncode(header.bytes()), JwtHelper.PERIOD, b64UrlEncode(content));
	}

	/**
	 * Allows retrieval of the full token.
	 *
	 * @return the encoded header, claims and crypto segments concatenated with "." characters
	 */
	public byte[] bytes() {
		return concat(b64UrlEncode(header.bytes()), JwtHelper.PERIOD, b64UrlEncode(content), JwtHelper.PERIOD,
				b64UrlEncode(crypto));
	}

	public String getClaims() {
		return utf8Decode(content);
	}

	public String getEncoded() {
		return utf8Decode(bytes());
	}

	@Override
	public String toString() {
		return header + " " + claims + " [" + crypto.length + " crypto bytes]";
	}
}
