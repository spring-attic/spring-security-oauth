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

import org.springframework.core.ConfigurableObjectInputStream;

import java.io.*;

/**
 * The default {@link SerializationStrategy} which uses the built-in Java serialization mechanism.
 * <p>
 * Note that this class should not be used if data for deserialization comes from an untrusted source.
 * Instead, please use {@link WhitelistedSerializationStrategy} with a list of allowed classes for deserialization.
 *
 * @author Artem Smotrakov
 * @since 2.4
 */
public class DefaultSerializationStrategy implements SerializationStrategy {

    public byte[] serialize(Object state) {
        ObjectOutputStream oos = null;
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream(512);
            oos = new ObjectOutputStream(bos);
            oos.writeObject(state);
            oos.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        } finally {
            if (oos != null) {
                try {
                    oos.close();
                } catch (IOException e) {
                    // eat it
                }
            }
        }
    }

    public <T> T deserialize(byte[] byteArray) {
        ObjectInputStream oip = null;
        try {
            oip = createObjectInputStream(byteArray);
            @SuppressWarnings("unchecked")
            T result = (T) oip.readObject();
            return result;
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        } catch (ClassNotFoundException e) {
            throw new IllegalArgumentException(e);
        } finally {
            if (oip != null) {
                try {
                    oip.close();
                } catch (IOException e) {
                    // eat it
                }
            }
        }
    }

    /**
     * Creates an {@link ObjectInputStream} for deserialization.
     *
     * @param byteArray Data to be deserialized.
     * @return An instance of {@link ObjectInputStream} which should be used for deserialization.
     * @throws IOException If something went wrong.
     */
    protected ObjectInputStream createObjectInputStream(byte[] byteArray) throws IOException {
        return new ConfigurableObjectInputStream(new ByteArrayInputStream(byteArray),
                Thread.currentThread().getContextClassLoader());
    }
}
