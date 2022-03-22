/*
 * Copyright 2002-2011 the original author or authors.
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
package org.springframework.security.oauth2.provider.client;

import java.util.Collections;
import java.util.TreeSet;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.util.StringUtils;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author Dave Syer
 */
class BaseClientDetailsTests {

    /**
     * test default constructor
     */
    @Test
    void testBaseClientDetailsDefaultConstructor() {
        BaseClientDetails details = new BaseClientDetails();
        assertEquals("[]", details.getResourceIds().toString());
        assertEquals("[]", details.getScope().toString());
        assertEquals("[]", details.getAuthorizedGrantTypes().toString());
        assertEquals("[]", details.getAuthorities().toString());
    }

    /**
     * test explicit convenience constructor
     */
    @Test
    void testBaseClientDetailsConvenienceConstructor() {
        BaseClientDetails details = new BaseClientDetails("foo", "", "foo,bar", "authorization_code", "ROLE_USER");
        assertEquals("[]", details.getResourceIds().toString());
        assertEquals("[bar, foo]", new TreeSet<String>(details.getScope()).toString());
        assertEquals("[authorization_code]", details.getAuthorizedGrantTypes().toString());
        assertEquals("[ROLE_USER]", details.getAuthorities().toString());
    }

    /**
     * test explicit autoapprove
     */
    @Test
    void testBaseClientDetailsAutoApprove() {
        BaseClientDetails details = new BaseClientDetails("foo", "", "foo,bar", "authorization_code", "ROLE_USER");
        details.setAutoApproveScopes(StringUtils.commaDelimitedListToSet("read,write"));
        assertTrue(details.isAutoApprove("read"));
    }

    @Test
    void testBaseClientDetailsImplicitAutoApprove() {
        BaseClientDetails details = new BaseClientDetails("foo", "", "foo,bar", "authorization_code", "ROLE_USER");
        details.setAutoApproveScopes(StringUtils.commaDelimitedListToSet("true"));
        assertTrue(details.isAutoApprove("read"));
    }

    @Test
    void testBaseClientDetailsNoAutoApprove() {
        BaseClientDetails details = new BaseClientDetails("foo", "", "foo,bar", "authorization_code", "ROLE_USER");
        details.setAutoApproveScopes(StringUtils.commaDelimitedListToSet("none"));
        assertFalse(details.isAutoApprove("read"));
    }

    @Test
    void testBaseClientDetailsNullAutoApprove() {
        BaseClientDetails details = new BaseClientDetails("foo", "", "foo,bar", "authorization_code", "ROLE_USER");
        assertFalse(details.isAutoApprove("read"));
    }

    @Test
    void testJsonSerialize() throws Exception {
        BaseClientDetails details = new BaseClientDetails("foo", "", "foo,bar", "authorization_code", "ROLE_USER");
        details.setClientId("foo");
        details.setClientSecret("bar");
        String value = new ObjectMapper().writeValueAsString(details);
        assertTrue(value.contains("client_id"));
        assertTrue(value.contains("client_secret"));
        assertTrue(value.contains("authorized_grant_types"));
        assertTrue(value.contains("[\"ROLE_USER\"]"));
    }

    @Test
    void testJsonSerializeAdditionalInformation() throws Exception {
        BaseClientDetails details = new BaseClientDetails("foo", "", "foo,bar", "authorization_code", "ROLE_USER");
        details.setClientId("foo");
        details.setAdditionalInformation(Collections.singletonMap("foo", "bar"));
        String value = new ObjectMapper().writeValueAsString(details);
        assertTrue(value.contains("\"foo\":\"bar\""));
    }

    @Test
    void testJsonDeserialize() throws Exception {
        String value = "{\"foo\":\"bar\",\"client_id\":\"foo\",\"scope\":[\"bar\",\"foo\"],\"authorized_grant_types\":[\"authorization_code\"],\"authorities\":[\"ROLE_USER\"]}";
        BaseClientDetails details = new ObjectMapper().readValue(value, BaseClientDetails.class);
        BaseClientDetails expected = new BaseClientDetails("foo", "", "foo,bar", "authorization_code", "ROLE_USER");
        expected.setAdditionalInformation(Collections.singletonMap("foo", (Object) "bar"));
        assertEquals(expected, details);
    }

    @Test
    void testJsonDeserializeWithArraysAsStrings() throws Exception {
        // Collection values can be deserialized from space or comma-separated lists
        String value = "{\"foo\":\"bar\",\"client_id\":\"foo\",\"scope\":\"bar  foo\",\"authorized_grant_types\":\"authorization_code\",\"authorities\":\"ROLE_USER,ROLE_ADMIN\"}";
        BaseClientDetails details = new ObjectMapper().readValue(value, BaseClientDetails.class);
        BaseClientDetails expected = new BaseClientDetails("foo", "", "foo,bar", "authorization_code", "ROLE_USER,ROLE_ADMIN");
        expected.setAdditionalInformation(Collections.singletonMap("foo", (Object) "bar"));
        assertEquals(expected, details);
    }

    /**
     * test equality
     */
    @Test
    void testEqualityOfValidity() {
        BaseClientDetails details = new BaseClientDetails();
        details.setAccessTokenValiditySeconds(100);
        BaseClientDetails other = new BaseClientDetails();
        other.setAccessTokenValiditySeconds(100);
        assertEquals(details, other);
    }
}
