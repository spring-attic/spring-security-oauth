package org.springframework.security.oauth2.provider.token.store.redis.jackson2;

import org.springframework.data.redis.serializer.SerializationException;
import org.springframework.security.oauth2.provider.token.store.redis.StandardStringSerializationStrategy;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * This is mostly working, but needs a lot of testing. RedisTokenStore passes
 * test when this serialization strategy is used, but real world usage is a bit
 * different due to polymorphism.
 *
 * @author efenderbosch
 *
 */
public class Jackson2SerializationStrategy extends StandardStringSerializationStrategy {

	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper().registerModule(new OAuth2JacksonModule());

	@Override
	protected <T> T deserializeInternal(byte[] bytes, Class<T> clazz) {
		try {
			return OBJECT_MAPPER.readValue(bytes, clazz);
		} catch (Exception e) {
			throw new SerializationException("Could not read JSON: " + e.getMessage(), e);
		}
	}

	@Override
	protected byte[] serializeInternal(Object object) {
		try {
			return OBJECT_MAPPER.writeValueAsBytes(object);
		} catch (Exception e) {
			throw new SerializationException("Could not write JSON: " + e.getMessage(), e);
		}
	}

}
