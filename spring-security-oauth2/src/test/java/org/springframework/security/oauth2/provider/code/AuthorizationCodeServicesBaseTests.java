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
	private static final int CODE_LIFETIME_FOREVER = Integer.MAX_VALUE;
	private static final int CODE_LIFETIME_EXPIRE_ON_CREATE = Integer.MIN_VALUE;

	abstract AuthorizationCodeServices getAuthorizationCodeServices(int codeLiftetimeSeconds);

	@Test
	public void testCreateAuthorizationCode() {
		OAuth2Request storedOAuth2Request = RequestTokenFactory.createOAuth2Request("id", false);
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(storedOAuth2Request,
				new TestAuthentication("test2", false));
		AuthorizationCodeServices authorizationCodeServices = getAuthorizationCodeServices(CODE_LIFETIME_FOREVER);

		String code = authorizationCodeServices.createAuthorizationCode(expectedAuthentication);
		assertNotNull(code);

		OAuth2Authentication actualAuthentication = authorizationCodeServices.consumeAuthorizationCode(code);
		assertEquals(expectedAuthentication, actualAuthentication);
	}

	@Test
	public void testConsumeRemovesCode() {
		OAuth2Request storedOAuth2Request = RequestTokenFactory.createOAuth2Request("id", false);
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(storedOAuth2Request,
				new TestAuthentication("test2", false));
		AuthorizationCodeServices authorizationCodeServices = getAuthorizationCodeServices(CODE_LIFETIME_FOREVER);
		String code = authorizationCodeServices.createAuthorizationCode(expectedAuthentication);
		assertNotNull(code);

		OAuth2Authentication actualAuthentication = authorizationCodeServices.consumeAuthorizationCode(code);
		assertEquals(expectedAuthentication, actualAuthentication);

		try {
			authorizationCodeServices.consumeAuthorizationCode(code);
			fail("Should have thrown exception");
		}
		catch (InvalidGrantException e) {
			// good we expected this
		}
	}

	@Test
	public void testConsumeNonExistingCode() {
		try {
			getAuthorizationCodeServices(CODE_LIFETIME_FOREVER).consumeAuthorizationCode("doesnt exist");
			fail("Should have thrown exception");
		}
		catch (InvalidGrantException e) {
			// good we expected this
		}
	}

	@Test
	public void testConsumeExpiredCode() {
		OAuth2Request storedOAuth2Request = RequestTokenFactory.createOAuth2Request("id", false);
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(storedOAuth2Request,
			new TestAuthentication("test2", false));
		AuthorizationCodeServices authorizationCodeServices = getAuthorizationCodeServices(
			CODE_LIFETIME_EXPIRE_ON_CREATE);
		String code = authorizationCodeServices.createAuthorizationCode(expectedAuthentication);
		assertNotNull(code);

		try {
			authorizationCodeServices.consumeAuthorizationCode(code);
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
