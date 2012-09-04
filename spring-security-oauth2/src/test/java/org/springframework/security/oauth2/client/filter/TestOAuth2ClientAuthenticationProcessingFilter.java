package org.springframework.security.oauth2.client.filter;/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */

import junit.framework.TestCase;
import org.junit.Test;
import org.springframework.security.oauth2.client.http.AccessTokenRequiredException;

import javax.servlet.ServletException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class TestOAuth2ClientAuthenticationProcessingFilter extends TestCase {

    Map<String, String> userInfo = new HashMap<String, String>();
    OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter("some-url");

    public void setUp() {
        userInfo = new HashMap<String, String>();
        userInfo.put("id", "user1");
    }

    @Test
    public void testGetUserId() {
        Map<String, String> userInfo = new HashMap<String, String>();
        assertNull(filter.getUserId(userInfo));

        userInfo.put("user_id", "userid1");
        assertEquals("userid1", filter.getUserId(userInfo));

        userInfo.put("id", "id1");
        assertEquals("id1", filter.getUserId(userInfo));

        userInfo.remove("user_id");
        assertEquals("id1", filter.getUserId(userInfo));
    }

    @Test
    public void testGetUserName() {
        Map<String, String> userInfo = new HashMap<String, String>();
        assertNull(filter.getUserName(userInfo));

        userInfo.put("id", "id1");
        assertEquals("id1", filter.getUserName(userInfo));

        userInfo.put("screen_name", "screen_name");
        userInfo.put("username", "username");
        userInfo.put("user_name", "user_name");
        userInfo.put("login", "login");
        userInfo.put("email", "email");
        assertEquals("username", filter.getUserName(userInfo));
    }

    @Test
    public void testUnsuccessfulAuthentication() throws IOException, ServletException {
        try {
            filter.unsuccessfulAuthentication(null, null, new AccessTokenRequiredException("testing", null));
            fail("AccessTokenRedirectException must be thrown");
        } catch (AccessTokenRequiredException ex) {

        }
    }
}
