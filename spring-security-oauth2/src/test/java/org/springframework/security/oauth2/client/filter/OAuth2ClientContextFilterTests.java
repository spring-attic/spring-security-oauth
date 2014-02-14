package org.springframework.security.oauth2.client.filter;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * @author Ryan Heaton
 */
public class OAuth2ClientContextFilterTests {

	@Test
	public void testVanillaCurrentUri() throws Exception {
		OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setQueryString("foo=bar");
		assertEquals("http://localhost?foo=bar", filter.calculateCurrentUri(request));
	}

	@Test
	public void testCurrentUriWithLegalSpaces() throws Exception {
		OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setQueryString("foo=bar%20spam");
		assertEquals("http://localhost?foo=bar%20spam", filter.calculateCurrentUri(request));
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
		assertEquals("http://localhost?foo=bar+spam", filter.calculateCurrentUri(request));
	}

	@Test
	public void testCurrentUriRemovingCode() throws Exception {
		OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setQueryString("code=XXXX&foo=bar");
		assertEquals("http://localhost?foo=bar", filter.calculateCurrentUri(request));
	}

	@Test
	public void testCurrentUriRemovingCodeInSecond() throws Exception {
		OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setQueryString("foo=bar&code=XXXX");
		assertEquals("http://localhost?foo=bar", filter.calculateCurrentUri(request));
	}

	@Test
	public void testCurrentUriWithInvalidQueryString() throws Exception {
		OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setQueryString("foo=bar&code=XXXX&parm=%xx");
		assertEquals(null, filter.calculateCurrentUri(request));
	}
}
