package org.springframework.security.oauth2.provider.token.store.redis;

/**
 * @author efenderbosch
 */
public interface RedisTokenStoreSerializationStrategy {

	<T> T deserialize(byte[] bytes, Class<T> clazz);

	String deserializeString(byte[] bytes);

	byte[] serialize(Object object);

	byte[] serialize(String data);

}
