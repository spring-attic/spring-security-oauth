package org.springframework.security.oauth2.client.filter;

import static org.junit.Assert.assertEquals;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.web.RedirectStrategy;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class OAuth2ClientContextFilterTests {

	@Test
	public void testVanillaRedirectUri() throws Exception {
		String redirect = "http://example.com/authorize";
		Map<String, String> params = new LinkedHashMap<String, String>();
		params.put("foo", "bar");
		params.put("scope", "spam");
		testRedirectUri(redirect, params, redirect + "?foo=bar&scope=spam");
	}

	@Test
	public void testTwoScopesRedirectUri() throws Exception {
		String redirect = "http://example.com/authorize";
		Map<String, String> params = new LinkedHashMap<String, String>();
		params.put("foo", "bar");
		params.put("scope", "spam scope2");
		testRedirectUri(redirect, params, redirect + "?foo=bar&scope=spam%20scope2");
	}

	@Test
	public void testRedirectUriWithUrlInParams() throws Exception {
		String redirect = "http://example.com/authorize";
		Map<String, String> params = Collections.singletonMap("redirect",
				"http://foo/bar");
		testRedirectUri(redirect, params, redirect + "?redirect=http://foo/bar");
	}

	@Test
	public void testRedirectUriWithQuery() throws Exception {
		String redirect = "http://example.com/authorize?foo=bar";
		Map<String, String> params = Collections.singletonMap("spam",
				"bucket");
		testRedirectUri(redirect, params, redirect + "&spam=bucket");
	}

	public void testRedirectUri(String redirect, Map<String, String> params,
			String result) throws Exception {
		OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
		RedirectStrategy redirectStrategy = Mockito
				.mock(RedirectStrategy.class);
		filter.setRedirectStrategy(redirectStrategy);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		UserRedirectRequiredException exception = new UserRedirectRequiredException(
				redirect, params);
		filter.redirectUser(exception, request, response);
		Mockito.verify(redirectStrategy)
				.sendRedirect(request, response, result);
	}

	@Test
	public void testVanillaCurrentUri() throws Exception {
		OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setQueryString("foo=bar");
		assertEquals("http://localhost?foo=bar",
				filter.calculateCurrentUri(request));
	}

	@Test
	public void testCurrentUriWithLegalSpaces() throws Exception {
		OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setQueryString("foo=bar%20spam");
		assertEquals("http://localhost?foo=bar%20spam",
				filter.calculateCurrentUri(request));
	}

	@Test
	public void testCurrentUriWithNoQuery() throws Exception {
		OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
		MockHttpServletRequest request = new MockHttpServletRequest();
		assertEquals("http://localhost", filter.calculateCurrentUri(request));
	}

	@Test
	public void testCurrentUriWithIllegalSpaces() throws Exception {
		OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setQueryString("foo=bar+spam");
		assertEquals("http://localhost?foo=bar+spam",
				filter.calculateCurrentUri(request));
	}

	@Test
	public void testCurrentUriRemovingCode() throws Exception {
		OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setQueryString("code=XXXX&foo=bar");
		assertEquals("http://localhost?foo=bar",
				filter.calculateCurrentUri(request));
	}

	@Test
	public void testCurrentUriRemovingCodeInSecond() throws Exception {
		OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setQueryString("foo=bar&code=XXXX");
		assertEquals("http://localhost?foo=bar",
				filter.calculateCurrentUri(request));
	}

	@Test
	public void testCurrentUriWithInvalidQueryString() throws Exception {
		OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setQueryString("foo=bar&code=XXXX&parm=%xx");
		try {
			assertEquals(null, filter.calculateCurrentUri(request));
		} catch (IllegalStateException ex) {
			// OAuth2ClientContextFilter.calculateCurrentUri() internally uses
			// ServletUriComponentsBuilder.fromRequest(), which behaves differently in Spring Framework 5
			// and throws an IllegalStateException for a malformed URI.
			// Previous to Spring Framework 5, 'null' would be returned by OAuth2ClientContextFilter.calculateCurrentUri()
			// instead of the thrown IllegalStateException.
		}
	}
}
