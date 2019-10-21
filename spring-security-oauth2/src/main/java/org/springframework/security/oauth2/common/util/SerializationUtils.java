/*
 * Copyright 2012-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.common.util;

import org.springframework.core.io.support.SpringFactoriesLoader;
import org.springframework.util.Assert;

import java.util.List;

/**
 * This is a helper class for serializing and deserializing objects with a {@link SerializationStrategy}.
 * The class looks for the strategy in {@code META-INF/spring.factories},
 * or the strategy can also be set by calling {@link #setSerializationStrategy(SerializationStrategy)}.
 * If no strategy is specified, the default is {@link DefaultSerializationStrategy}.
 * <p>
 * Note that the default strategy allows deserializing arbitrary classes which may result in security problems
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
        Assert.notNull(serializationStrategy, "serializationStrategy cannot be null");
        strategy = serializationStrategy;
    }

    public static byte[] serialize(Object object) {
        return strategy.serialize(object);
    }

    public static <T> T deserialize(byte[] byteArray) {
        return strategy.deserialize(byteArray);
    }

}