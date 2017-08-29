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

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.jwt.codec.Codecs;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * A {@link Converter} that converts the supplied <code>String</code> representation of a JWT
 * to a <code>Map</code> of JWT Header Parameters.
 *
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7519">JSON Web Token (JWT)</a>
 *
 * @author Joe Grandja
 * @author Vedran Pavic
 */
class JwtHeaderConverter implements Converter<String, Map<String, String>> {
	private final JsonFactory factory = new JsonFactory();

	/**
	 * Converts the supplied JSON Web Token to a <code>Map</code> of JWT Header Parameters.
	 *
	 * @param token the JSON Web Token
	 * @return a <code>Map</code> of JWT Header Parameters
	 * @throws InvalidTokenException if the JWT is invalid
	 */
	@Override
	public Map<String, String> convert(String token) {
		Map<String, String> headers;

		int headerEndIndex = token.indexOf('.');
		if (headerEndIndex == -1) {
			throw new InvalidTokenException("Invalid JWT. Missing JOSE Header.");
		}

		byte[] decodedHeader;

		try {
			decodedHeader = Codecs.b64UrlDecode(token.substring(0, headerEndIndex));
		} catch (IllegalArgumentException ex) {
			throw new InvalidTokenException("Invalid JWT. Malformed JOSE Header.", ex);
		}

		JsonParser parser = null;

		try {
			parser = this.factory.createParser(decodedHeader);
			headers = new HashMap<String, String>();
			if (parser.nextToken() == JsonToken.START_OBJECT) {
				while (parser.nextToken() == JsonToken.FIELD_NAME) {
					String headerName = parser.getCurrentName();
					parser.nextToken();
					String headerValue = parser.getValueAsString();
					headers.put(headerName, headerValue);
				}
			}

		} catch (IOException ex) {
			throw new InvalidTokenException("An I/O error occurred while reading the JWT: " + ex.getMessage(), ex);
		} finally {
			try {
				if (parser != null) parser.close();
			} catch (IOException ex) { }
		}

		return headers;
	}
}
