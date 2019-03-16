/*
 * Copyright 2012-2020 the original author or authors.
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

import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Tests for {@link RandomValueStringGenerator}
 *
 * @author Josh Kerr
 */
public class RandomValueStringGeneratorTests {

    private RandomValueStringGenerator generator;

    @Before
    public void setup() {
        generator = new RandomValueStringGenerator();
    }

    @Test
    public void generate() {
        String value = generator.generate();
        assertNotNull(value);
        assertEquals("Authorization code is not correct size", 6, value.length());
    }

    @Test
    public void generate_LargeLengthOnConstructor() {
        generator = new RandomValueStringGenerator(1024);
        String value = generator.generate();
        assertNotNull(value);
        assertEquals("Authorization code is not correct size", 1024, value.length());
    }

    @Test
    public void getAuthorizationCodeString() {
        byte[] bytes = new byte[10];
        new SecureRandom().nextBytes(bytes);
        String value = generator.getAuthorizationCodeString(bytes);
        assertNotNull(value);
        assertEquals("Authorization code is not correct size", 10, value.length());
    }

    @Test
    public void setLength() {
        generator.setLength(12);
        String value = generator.generate();
        assertEquals("Authorization code is not correct size", 12, value.length());
    }

    @Test(expected = IllegalArgumentException.class)
    public void setLength_NonPositiveNumber() {
        generator.setLength(-1);
        generator.generate();
    }
}