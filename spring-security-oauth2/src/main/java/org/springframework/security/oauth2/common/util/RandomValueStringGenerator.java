/*
 * Copyright 2012-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.common.util;

import java.security.SecureRandom;
import java.util.Random;

/**
 * Utility that generates a random-value ASCII string.
 *
 * <p>
 * @deprecated See the <a href="https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide">OAuth 2.0 Migration Guide</a> for Spring Security 5.
 *
 * @author Ryan Heaton
 * @author Dave Syer
 */
@Deprecated
public class RandomValueStringGenerator {

	private static final char[] DEFAULT_CODEC = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_"
			.toCharArray();

	private Random random = new SecureRandom();

	private int length;

	/**
	 * Create a generator with the default length (6).
	 */
	public RandomValueStringGenerator() {
		this(6);
	}

	/**
	 * Create a generator of random strings of the length provided
	 * 
	 * @param length the length of the strings generated
	 */
	public RandomValueStringGenerator(int length) {
		this.length = length;
	}

	public String generate() {
		byte[] verifierBytes = new byte[length];
		random.nextBytes(verifierBytes);
		return getAuthorizationCodeString(verifierBytes);
	}

	/**
	 * Convert these random bytes to a verifier string. The length of the byte array can be
	 * {@link #setLength(int) configured}. The default implementation mods the bytes to fit into the
	 * ASCII letters 1-9, A-Z, a-z, -_ .
	 * 
	 * @param verifierBytes The bytes.
	 * @return The string.
	 */
	protected String getAuthorizationCodeString(byte[] verifierBytes) {
		char[] chars = new char[verifierBytes.length];
		for (int i = 0; i < verifierBytes.length; i++) {
			chars[i] = DEFAULT_CODEC[((verifierBytes[i] & 0xFF) % DEFAULT_CODEC.length)];
		}
		return new String(chars);
	}

	/**
	 * The random value generator used to create token secrets.
	 * 
	 * @param random The random value generator used to create token secrets.
	 */
	public void setRandom(Random random) {
		this.random = random;
	}
	
	/**
	 * The length of string to generate.  A length less than or equal to 0 will result in an {@code IllegalArgumentException}.
	 * 
	 * @param length the length to set
	 */
	public void setLength(int length) {
		if (length <= 0) {
			throw new IllegalArgumentException("length must be greater than 0");
		}
		this.length = length;
	}

}
