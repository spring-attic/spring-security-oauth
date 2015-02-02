package org.springframework.security.oauth2.provider.token.store.redis.jackson2;

import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

public class OAuth2AuthenticationDeserializer extends StdDeserializer<OAuth2Authentication> {

	private static final Logger log = LoggerFactory.getLogger(OAuth2AuthenticationDeserializer.class);

	private static final long serialVersionUID = 1L;

	public OAuth2AuthenticationDeserializer() {
		super(OAuth2Authentication.class);
	}

	@Override
	public OAuth2Authentication deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException,
	JsonProcessingException {
		String details = null;
		OAuth2Request request = null;
		Authentication userAuthentication = null;
		List<? extends GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		boolean authenticated = false;
		String principal = null;
		String credentials = null;
		String name = null;
		while (jp.nextToken() != JsonToken.END_OBJECT) {
			String token = jp.getCurrentName();
			jp.nextToken();
			if (token == null) {
				log.warn("name is null");
				break;
			}
			if (token.equals("details")) {
				details = jp.getValueAsString();
				continue;
			}
			if (token.equals("oauth2Request")) {
				request = jp.readValueAs(OAuth2Request.class);
				continue;
			}
			if (token.equals("userAuthentication")) {
				userAuthentication = jp.readValueAs(Authentication.class);
				continue;
			}
			if (token.equals("authorities")) {
				authorities = jp.readValueAs(authorities.getClass());
				continue;
			}
			if (token.equals("authenticated")) {
				authenticated = jp.getValueAsBoolean();
				continue;
			}
			if (token.equals("principal")) {
				principal = jp.getValueAsString();
				continue;
			}
			if (token.equals("credentials")) {
				credentials = jp.getValueAsString();
				continue;
			}
			if (token.equals("name")) {
				name = jp.getValueAsString();
				continue;
			}
			if (token.equals("clientOnly")) {
				// read only
				continue;
			}
			log.warn("unknown name {}", token);
		}

		if (request == null) {
			// log.warn("request is null");
			Map<String, String> requestParameters = new HashMap<String, String>();
			Set<String> scope = new HashSet<String>();
			Set<String> resourceIds = new HashSet<String>();
			String redirectUri = null;
			Set<String> responseTypes = new HashSet<String>();
			Map<String, Serializable> extensionProperties = new HashMap<String, Serializable>();
			request = new OAuth2Request(requestParameters, principal, authorities, authenticated, scope, resourceIds,
					redirectUri, responseTypes, extensionProperties);
		}

		if (userAuthentication == null) {
			// log.warn("userAuthentication is null");
			userAuthentication = new OAuth2Authentication(request, null);
		}

		OAuth2Authentication authentication = new OAuth2Authentication(request, userAuthentication);
		if (details != null) {
			authentication.setDetails(details);
		}
		return authentication;
	}

}
