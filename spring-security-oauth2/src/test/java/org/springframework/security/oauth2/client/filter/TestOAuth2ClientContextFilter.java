package org.springframework.security.oauth2.client.filter;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * @author Ryan Heaton
 */
public class TestOAuth2ClientContextFilter {

	@Test
	public void testVanillaCurrentUri() throws Exception {
		OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter("foo", "bar");
		assertEquals("http://localhost?foo=bar", filter.calculateCurrentUri(request));
	}

	@Test
	public void testCurrentUriRemovingCode() throws Exception {
		OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter("code", "XXXX");
		request.addParameter("foo", "bar");
		assertEquals("http://localhost?foo=bar", filter.calculateCurrentUri(request));
	}

}
