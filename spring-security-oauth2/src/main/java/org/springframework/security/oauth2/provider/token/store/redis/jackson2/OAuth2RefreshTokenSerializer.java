package org.springframework.security.oauth2.provider.token.store.redis.jackson2;

import java.io.IOException;

import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.fasterxml.jackson.databind.util.ISO8601Utils;

public class OAuth2RefreshTokenSerializer extends StdSerializer<OAuth2RefreshToken> {

	static final String VALUE = "value";
	static final String EXPIRATION = "expiration";

	public OAuth2RefreshTokenSerializer() {
		super(OAuth2RefreshToken.class);
	}

	@Override
	public void serialize(OAuth2RefreshToken refreshToken, JsonGenerator jgen, SerializerProvider provider)
			throws IOException, JsonGenerationException {
		jgen.writeStartObject();
		jgen.writeStringField(VALUE, refreshToken.getValue());
		if (refreshToken instanceof ExpiringOAuth2RefreshToken) {
			ExpiringOAuth2RefreshToken expiringRefreshToken = (ExpiringOAuth2RefreshToken) refreshToken;
			if (expiringRefreshToken.getExpiration() != null) {
				String date = ISO8601Utils.format(expiringRefreshToken.getExpiration());
				jgen.writeStringField(EXPIRATION, date);
			}
		}
		jgen.writeEndObject();
	}

}
