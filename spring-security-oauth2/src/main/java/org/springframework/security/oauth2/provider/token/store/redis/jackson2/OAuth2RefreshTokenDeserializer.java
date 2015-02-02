package org.springframework.security.oauth2.provider.token.store.redis.jackson2;

import java.io.IOException;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.util.ISO8601Utils;

public class OAuth2RefreshTokenDeserializer extends StdDeserializer<OAuth2RefreshToken> {

	private static final Logger log = LoggerFactory.getLogger(OAuth2RefreshTokenDeserializer.class);

	private static final long serialVersionUID = 1L;

	public OAuth2RefreshTokenDeserializer() {
		super(OAuth2RefreshToken.class);
	}

	@Override
	public OAuth2RefreshToken deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException,
	JsonProcessingException {

		String value = null;
		Date expiration = null;
		while (jp.nextToken() != JsonToken.END_OBJECT) {
			String name = jp.getCurrentName();
			jp.nextToken();
			if (name.equals(OAuth2RefreshTokenSerializer.VALUE)) {
				value = jp.getText();
				continue;
			}
			if (name.equals(OAuth2RefreshTokenSerializer.EXPIRATION)) {
				try {
					expiration = ISO8601Utils.parse(jp.getText());
				} catch (IllegalArgumentException e) {
					throw new JsonParseException("error parsing expiration", jp.getCurrentLocation(), e);
				}
				continue;
			}
			log.warn("unknown name {}", name);
		}
		if (value == null) {
			return null;
		}
		if (expiration == null) {
			return new DefaultOAuth2RefreshToken(value);
		}
		return new DefaultExpiringOAuth2RefreshToken(value, expiration);
	}

}
