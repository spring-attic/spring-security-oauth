package org.springframework.security.oauth2.consumer;

import junit.framework.TestCase;

import org.springframework.mock.web.MockHttpServletRequest;

/**
 * @author Ryan Heaton
 */
public class TestOAuth2ClientContextFilter extends TestCase {

	public void testVanillaCurrentUri() throws Exception {
		OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter("foo", "bar");
		assertEquals("http://localhost?foo=bar", filter.calculateCurrentUri(request));
	}

	public void testCurrentUriRemovingCode() throws Exception {
		OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter("code", "XXXX");
		request.addParameter("foo", "bar");
		assertEquals("http://localhost?foo=bar", filter.calculateCurrentUri(request));
	}

}
