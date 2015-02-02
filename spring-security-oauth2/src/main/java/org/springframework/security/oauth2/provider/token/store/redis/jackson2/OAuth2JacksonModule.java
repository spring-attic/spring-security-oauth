package org.springframework.security.oauth2.provider.token.store.redis.jackson2;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import com.fasterxml.jackson.databind.module.SimpleModule;

public class OAuth2JacksonModule extends SimpleModule {

	private static final long serialVersionUID = 1L;

	public OAuth2JacksonModule() {
		addDeserializer(OAuth2RefreshToken.class, new OAuth2RefreshTokenDeserializer());
		addSerializer(OAuth2RefreshToken.class, new OAuth2RefreshTokenSerializer());
		addDeserializer(OAuth2Authentication.class, new OAuth2AuthenticationDeserializer());
		addAbstractTypeMapping(Authentication.class, OAuth2Authentication.class);
		addDeserializer(OAuth2Request.class, new OAuth2RequestDeserializer());
	}

}