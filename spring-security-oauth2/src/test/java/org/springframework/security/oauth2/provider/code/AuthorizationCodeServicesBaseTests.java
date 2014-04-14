package org.springframework.security.oauth2.provider.code;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import org.junit.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.RequestTokenFactory;

public abstract class AuthorizationCodeServicesBaseTests {

	abstract AuthorizationCodeServices getAuthorizationCodeServices();

	@Test
	public void testCreateAuthorizationCode() {
		OAuth2Request storedOAuth2Request = RequestTokenFactory.createOAuth2Request("id", false);
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(storedOAuth2Request,
				new TestAuthentication("test2", false));
		String code = getAuthorizationCodeServices().createAuthorizationCode(expectedAuthentication);
		assertNotNull(code);

		OAuth2Authentication actualAuthentication = getAuthorizationCodeServices().consumeAuthorizationCode(code);
		assertEquals(expectedAuthentication, actualAuthentication);
	}

	@Test
	public void testConsumeRemovesCode() {
		OAuth2Request storedOAuth2Request = RequestTokenFactory.createOAuth2Request("id", false);
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(storedOAuth2Request,
				new TestAuthentication("test2", false));
		String code = getAuthorizationCodeServices().createAuthorizationCode(expectedAuthentication);
		assertNotNull(code);

		OAuth2Authentication actualAuthentication = getAuthorizationCodeServices().consumeAuthorizationCode(code);
		assertEquals(expectedAuthentication, actualAuthentication);

		try {
			getAuthorizationCodeServices().consumeAuthorizationCode(code);
			fail("Should have thrown exception");
		}
		catch (InvalidGrantException e) {
			// good we expected this
		}
	}

	@Test
	public void testConsumeNonExistingCode() {
		try {
			getAuthorizationCodeServices().consumeAuthorizationCode("doesnt exist");
			fail("Should have thrown exception");
		}
		catch (InvalidGrantException e) {
			// good we expected this
		}
	}

	protected static class TestAuthentication extends AbstractAuthenticationToken {

		private static final long serialVersionUID = 1L;

		private String principal;

		public TestAuthentication(String name, boolean authenticated) {
			super(null);
			setAuthenticated(authenticated);
			this.principal = name;
		}

		public Object getCredentials() {
			return null;
		}

		public Object getPrincipal() {
			return this.principal;
		}
	}

}
