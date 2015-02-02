package org.springframework.security.oauth2.provider.token.store.redis;

import org.springframework.data.redis.serializer.StringRedisSerializer;

/**
 * Serializes Strings using {@link StringRedisSerializer}
 * 
 * @author efenderbosch
 *
 */
public abstract class StandardStringSerializationStrategy extends BaseRedisTokenStoreSerializationStrategy {

	private static final StringRedisSerializer STRING_SERIALIZER = new StringRedisSerializer();

	@Override
	protected String deserializeStringInternal(byte[] bytes) {
		return STRING_SERIALIZER.deserialize(bytes);
	}

	@Override
	protected byte[] serializeInternal(String string) {
		return STRING_SERIALIZER.serialize(string);
	}

}
