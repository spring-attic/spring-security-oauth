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

/**
 * Defines how objects are serialized and deserialized.
 *
 * <p>
 * @deprecated See the <a href="https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide">OAuth 2.0 Migration Guide</a> for Spring Security 5.
 *
 * @author Artem Smotrakov
 * @since 2.4
 */
@Deprecated
public interface SerializationStrategy {

    /**
     * Serializes an object.
     *
     * @param object The object to be serialized.
     * @return A byte array.
     */
    byte[] serialize(Object object);

    /**
     * Deserializes an object from a byte array.
     *
     * @param byteArray The byte array.
     * @param <T>       The type of the object.
     * @return The deserialized object.
     */
    <T> T deserialize(byte[] byteArray);

}
