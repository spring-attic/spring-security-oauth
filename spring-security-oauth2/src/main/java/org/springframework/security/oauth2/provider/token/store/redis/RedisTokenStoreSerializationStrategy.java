package org.springframework.security.oauth2.provider.token.store.redis;

/**
 * <p>
 * @deprecated See the <a href="https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide">OAuth 2.0 Migration Guide</a> for Spring Security 5.
 *
 * @author efenderbosch
 */
@Deprecated
public interface RedisTokenStoreSerializationStrategy {

	<T> T deserialize(byte[] bytes, Class<T> clazz);

	String deserializeString(byte[] bytes);

	byte[] serialize(Object object);

	byte[] serialize(String data);

}
