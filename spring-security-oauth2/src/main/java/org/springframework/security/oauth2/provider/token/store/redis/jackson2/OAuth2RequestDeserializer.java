package org.springframework.security.oauth2.provider.token.store.redis.jackson2;

import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.OAuth2Request;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

public class OAuth2RequestDeserializer extends StdDeserializer<OAuth2Request> {

	private static final Logger log = LoggerFactory.getLogger(OAuth2RequestDeserializer.class);

	private static final long serialVersionUID = 1L;

	public OAuth2RequestDeserializer() {
		super(OAuth2Request.class);
	}

	@Override
	public OAuth2Request deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException,
	JsonProcessingException {

		Map<String, String> requestParameters = new HashMap<String, String>();
		String clientId = null;
		Collection<? extends GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		boolean approved = false;
		Set<String> scope = new HashSet<String>();
		Set<String> resourceIds = new HashSet<String>();
		String redirectUri = null;
		Set<String> responseTypes = new HashSet<String>();
		Map<String, Serializable> extensions = new HashMap<String, Serializable>();

		while (jp.nextToken() != JsonToken.END_OBJECT) {
			String name = jp.getCurrentName();
			jp.nextToken();
			if (name.equals("requestParameters")) {
				requestParameters = jp.readValueAs(requestParameters.getClass());
				continue;
			}
			if (name.equalsIgnoreCase("clientId")) {
				clientId = jp.getValueAsString();
				continue;
			}
			if (name.equals("authorities")) {
				authorities = jp.readValueAs(authorities.getClass());
				continue;
			}
			if (name.equals("approved")) {
				approved = jp.getValueAsBoolean();
				continue;
			}
			if (name.equals("scope")) {
				scope = jp.readValueAs(scope.getClass());
				continue;
			}
			if (name.equals("resourceIds")) {
				resourceIds = jp.readValueAs(resourceIds.getClass());
				continue;
			}
			if (name.equals("redirectUri")) {
				redirectUri = jp.getValueAsString();
				continue;
			}
			if (name.equals("responseTypes")) {
				responseTypes = jp.readValueAs(responseTypes.getClass());
				continue;
			}
			if (name.equals("extensions")) {
				extensions = jp.readValueAs(extensions.getClass());
				continue;
			}
			if (name.equals("grantType")) {
				// read only
				continue;
			}
			log.warn("unknown name {}", name);
		}
		OAuth2Request request = new OAuth2Request(requestParameters, clientId, authorities, approved, scope,
				resourceIds, redirectUri, responseTypes, extensions);

		return request;
	}

}
