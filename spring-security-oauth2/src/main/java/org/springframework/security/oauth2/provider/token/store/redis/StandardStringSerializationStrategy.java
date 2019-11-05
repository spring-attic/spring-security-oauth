package org.springframework.security.oauth2.provider.token.store.redis;

import org.springframework.data.redis.serializer.StringRedisSerializer;

/**
 * Serializes Strings using {@link StringRedisSerializer}
 *
 * <p>
 * @deprecated See the <a href="https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide">OAuth 2.0 Migration Guide</a> for Spring Security 5.
 *
 * @author efenderbosch
 *
 */
@Deprecated
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
