package org.springframework.security.oauth2.provider;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collections;

import org.codehaus.jackson.map.ObjectMapper;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class TestOAuth2Authentication {

	private DefaultAuthorizationRequest request = new DefaultAuthorizationRequest("id", Arrays.asList("read"));

	private UsernamePasswordAuthenticationToken userAuthentication = new UsernamePasswordAuthenticationToken("foo",
			"bar", Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));

	@Test
	public void testIsAuthenticated() {
		request.setApproved(true);
		OAuth2Authentication authentication = new OAuth2Authentication(request, userAuthentication);
		assertTrue(authentication.isAuthenticated());
	}

	@Test
	public void testGetCredentials() {
		OAuth2Authentication authentication = new OAuth2Authentication(request, userAuthentication);
		assertEquals("", authentication.getCredentials());
	}

	@Test
	public void testGetPrincipal() {
		OAuth2Authentication authentication = new OAuth2Authentication(request, userAuthentication);
		assertEquals(userAuthentication.getPrincipal(), authentication.getPrincipal());
	}

	@Test
	public void testIsClientOnly() {
		OAuth2Authentication authentication = new OAuth2Authentication(request, null);
		assertTrue(authentication.isClientOnly());
	}
	
	@Test
	public void testJsonSerialization() throws Exception {
		System.err.println(new ObjectMapper().writeValueAsString(new OAuth2Authentication(request, userAuthentication)));
	}

}
