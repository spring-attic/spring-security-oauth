package org.springframework.security.oauth2.provider.token;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * Created with IntelliJ IDEA. User: saket Date: 29/09/2014 Time: 16:25 To change this template use File | Settings |
 * File Templates.
 */

public class DefaultUserAuthenticationConverterTests {
	private DefaultUserAuthenticationConverter converter = new DefaultUserAuthenticationConverter();

	@Test
	public void shouldExtractAuthenticationWhenAuthoritiesIsCollection() throws Exception {
		Map<String, Object> map = new HashMap<String, Object>();
		map.put(UserAuthenticationConverter.USERNAME, "test_user");
		ArrayList<String> lists = new ArrayList<String>();
		lists.add("a1");
		lists.add("a2");
		map.put(UserAuthenticationConverter.AUTHORITIES, lists);

		Authentication authentication = converter.extractAuthentication(map);

		assertEquals(2, authentication.getAuthorities().size());
	}

	@Test
	public void shouldExtractAuthenticationWhenAuthoritiesIsString() throws Exception {
		Map<String, Object> map = new HashMap<String, Object>();
		map.put(UserAuthenticationConverter.USERNAME, "test_user");
		map.put(UserAuthenticationConverter.AUTHORITIES, "a1,a2");

		Authentication authentication = converter.extractAuthentication(map);

		assertEquals(2, authentication.getAuthorities().size());
	}

	@Test
	public void shouldExtractAuthenticationWhenUserDetailsProvided() throws Exception {
		Map<String, Object> map = new HashMap<String, Object>();
		map.put(UserAuthenticationConverter.USERNAME, "test_user");

		UserDetailsService userDetailsService = Mockito.mock(UserDetailsService.class);
		Mockito.when(userDetailsService.loadUserByUsername("test_user")).thenReturn(
				new User("foo", "bar", AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_SPAM")));
		converter.setUserDetailsService(userDetailsService);
		Authentication authentication = converter.extractAuthentication(map);

		assertEquals("ROLE_SPAM", authentication.getAuthorities().iterator().next().toString());
	}
}
