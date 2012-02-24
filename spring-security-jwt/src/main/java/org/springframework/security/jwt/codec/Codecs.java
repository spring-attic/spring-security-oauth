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
package org.springframework.security.jwt.codec;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;

/**
 * Functions for Hex, Base64 and Utf8 encoding/decoding
 *
 * @author Luke Taylor
 */
public class Codecs {
	private static Charset UTF8 = Charset.forName("UTF-8");

	/**
	 * Base 64
	 */
	public static byte[] b64Encode(byte[] bytes) {
		return Base64Codec.encode(bytes);
	}

	public static byte[] b64Decode(byte[] bytes) {
		return Base64Codec.decode(bytes);
	}

	// URL-safe versions with no padding chars
	public static byte[] b64UrlEncode(byte[] bytes) {
		return Base64.urlEncode(bytes);
	}

	public static byte[] b64UrlEncode(CharSequence value) {
		return b64UrlEncode(utf8Encode(value));
	}

	public static byte[] b64UrlDecode(byte[] bytes) {
		return Base64.urlDecode(bytes);
	}

	public static byte[] b64UrlDecode(CharSequence value) {
		return b64UrlDecode(utf8Encode(value));
	}


	/**
	 * UTF-8 encoding/decoding. Using a charset rather than `String.getBytes` is less forgiving
	 * and will raise an exception for invalid data.
	 */
	public static byte[] utf8Encode(CharSequence string) {
		try {
			ByteBuffer bytes = UTF8.newEncoder().encode(CharBuffer.wrap(string));
			byte[] bytesCopy = new byte[bytes.limit()];
			System.arraycopy(bytes.array(), 0, bytesCopy, 0, bytes.limit());
			return bytesCopy;
		}
		catch (CharacterCodingException e) {
			throw new RuntimeException(e);
		}
	}

	public static String utf8Decode(byte[] bytes) {
		return utf8Decode(ByteBuffer.wrap(bytes));
	}

	public static String utf8Decode(ByteBuffer bytes) {
		try {
			return UTF8.newDecoder().decode(bytes).toString();
		}
		catch (CharacterCodingException e) {
			throw new RuntimeException(e);
		}
	}

	public static char[] hexEncode(byte[] bytes) {
		return Hex.encode(bytes);
	}

	public static byte[] hexDecode(CharSequence s) {
		return Hex.decode(s);
	}

	// Substitute for Scala's Array.concat()
	public static byte[] concat(byte[]... arrays) {
		int size = 0;
		for (byte[] a: arrays) {
			size += a.length;
		}
		byte[] result = new byte[size];
		int index = 0;
		for (byte[] a: arrays) {
			System.arraycopy(a, 0, result, index, a.length);
			index += a.length;
		}
		return result;
	}
}


class Base64 {
	private static byte EQUALS = (byte)'=';

	static byte[] encode(byte[] bytes) {
		return Base64Codec.encode(bytes);
	}

	static byte[] decode(byte[] bytes) {
		return Base64Codec.decode(bytes);
	}

	static byte[] urlEncode(byte[] bytes) {
		byte[] b64Bytes = Base64Codec.encodeBytesToBytes(bytes, 0, bytes.length, Base64Codec.URL_SAFE);

		int length = b64Bytes.length;

		while(b64Bytes[length - 1] == EQUALS) {
		  length -= 1;
		}

		byte[] result = new byte[length];
		System.arraycopy(b64Bytes, 0, result, 0, length);

		return result;
	}

	static byte[] urlDecode(byte[] b64) {
		// Pad with '=' as necessary before feeding to standard decoder
		byte[] b64Bytes = null;

		int lMod4 = b64.length % 4;

		if (lMod4 == 0) {
			b64Bytes = b64;
		} else if (lMod4 == 2) {
			b64Bytes = pad(b64, 2);
		} else if (lMod4 == 3) {
			b64Bytes = pad(b64, 1);
		} else {
			throw new IllegalArgumentException("Invalid Base64 string");
		}

		return Base64Codec.decode(b64Bytes, 0, b64Bytes.length, Base64Codec.URL_SAFE);
	}

	private static byte[] pad(byte[] bytes, int n) {
		int l = bytes.length;
		byte[] padded = new byte[l + n];
		System.arraycopy(bytes, 0, padded, 0, l);
		for (int i = l; i < l + n; i++) {
			padded[i] = EQUALS;
		}
		return padded;
	}
}

class Hex {
	private static final char[] HEX = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

	static char[] encode(byte[] bytes) {
		int nBytes = bytes.length;
		char[] result = new char[2 * nBytes];

		int j = 0;
		for (int i = 0; i < nBytes; i++) {
			// Char for top 4 bits
			result[j] = HEX[(0xF0 & bytes[i]) >>> 4];
			// Bottom 4
			result[j + 1] = HEX[(0x0F & bytes[i])];
			j += 2;
		}
		return result;
	}

	static byte[] decode(CharSequence s) {
		int nChars = s.length();
		if (nChars % 2 != 0) {
			throw new IllegalArgumentException("Hex-encoded string must have an even number of characters");
		}

		byte[] result = new byte[nChars / 2];

		for (int i = 0; i < nChars; i += 2) {
			int msb = Character.digit(s.charAt(i), 16);
			int lsb = Character.digit(s.charAt(i + 1), 16);
			if (msb <= 0 || lsb <= 0) {
				throw new IllegalArgumentException("Non-hex character in input: " + s);
			}
			result[i / 2] = (byte) ((msb << 4) | lsb);
		}
		return result;
	}
}
