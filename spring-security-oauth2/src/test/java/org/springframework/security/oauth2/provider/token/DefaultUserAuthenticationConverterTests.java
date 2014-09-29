package org.springframework.security.oauth2.provider.token;

import org.junit.Test;
import org.springframework.security.core.Authentication;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

/**
 * Created with IntelliJ IDEA.
 * User: saket
 * Date: 29/09/2014
 * Time: 16:25
 * To change this template use File | Settings | File Templates.
 */

public class DefaultUserAuthenticationConverterTests {
    private UserAuthenticationConverter converter = new DefaultUserAuthenticationConverter();

    @Test
    public void shouldExtractAuthenticationWhenAuthoritiesIsCollection() throws Exception {
        Map<String, Object> map = new HashMap<String, Object>();
        map.put(UserAuthenticationConverter.USERNAME, "test_user");
        ArrayList<String> lists = new ArrayList<String>();
        lists.add("a1");
        lists.add("a2");
        map.put(UserAuthenticationConverter.AUTHORITIES, lists);

        Authentication authentication = converter.extractAuthentication(map);

        assertNotEquals(authentication.getAuthorities(), null);
        assertEquals(authentication.getAuthorities().size(), 2);
    }

    @Test
    public void shouldExtractAuthenticationWhenAuthoritiesIsString() throws Exception {
        Map<String, Object> map = new HashMap<String, Object>();
        map.put(UserAuthenticationConverter.USERNAME, "test_user");
        map.put(UserAuthenticationConverter.AUTHORITIES, "a1,a2");

        Authentication authentication = converter.extractAuthentication(map);

        assertNotEquals(authentication.getAuthorities(), null);
        assertEquals(authentication.getAuthorities().size(), 2);
    }
}

