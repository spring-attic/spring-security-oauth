package org.springframework.security.oauth2.common.util;

import org.springframework.core.io.support.SpringFactoriesLoader;
import org.springframework.util.Assert;

import java.util.List;

/**
 * This is a helper class for serializing and deserializing objects with a {@link SerializationStrategy}.
 * The class looks for the strategy in {@code META-INF/spring.factories},
 * or the strategy can be also set by calling {@link #setSerializationStrategy(SerializationStrategy)} method.<br/>
 * If no strategy specified, the class uses {@link DefaultSerializationStrategy}.
 * <br/>
 * Note that the default strategy allows deserializing arbitrary classes which may result to security problems
 * if data comes from an untrusted source. To prevent possible issues, use {@link WhitelistedSerializationStrategy}
 * with a list of allowed classes for deserialization.
 */
public class SerializationUtils {

    private static SerializationStrategy strategy = new DefaultSerializationStrategy();

    static {
        List<SerializationStrategy> strategies = SpringFactoriesLoader.loadFactories(
                SerializationStrategy.class, SerializationUtils.class.getClassLoader());
        if (strategies.size() > 1) {
            throw new IllegalArgumentException(
                    "Too many serialization strategies in META-INF/spring.factories");
        }
        if (strategies.size() == 1) {
            strategy = strategies.get(0);
        }
    }

    /**
     * @return The current serialization strategy.
     */
    public static SerializationStrategy getSerializationStrategy() {
        return strategy;
    }

    /**
     * Sets a new serialization strategy.
     *
     * @param serializationStrategy The serialization strategy.
     */
    public static void setSerializationStrategy(SerializationStrategy serializationStrategy) {
        Assert.notNull(serializationStrategy, "Serialization strategy can't be null");
        strategy = serializationStrategy;
    }

    public static byte[] serialize(Object object) {
        return strategy.serialize(object);
    }

    public static <T> T deserialize(byte[] byteArray) {
        return strategy.deserialize(byteArray);
    }

}