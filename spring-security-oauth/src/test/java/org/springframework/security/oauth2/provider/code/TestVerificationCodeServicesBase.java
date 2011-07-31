package org.springframework.security.oauth2.provider.code;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.Serializable;
import java.util.Collection;

import org.junit.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.UnconfirmedAuthorizationCodeAuthenticationToken;

public abstract class TestVerificationCodeServicesBase {

	abstract AuthorizationCodeServices getVerificationCodeServices();

	@Test
	public void testCreateVerificationCode() {
		OAuth2Authentication<UnconfirmedAuthorizationCodeAuthenticationToken, TestAuthentication> expectedAuthentication = new OAuth2Authentication<UnconfirmedAuthorizationCodeAuthenticationToken, TestAuthentication>(
				new UnconfirmedAuthorizationCodeAuthenticationToken("id", null, null, null), new TestAuthentication("test2", false));
		String code = getVerificationCodeServices().createAuthorizationCode(expectedAuthentication);
		assertNotNull(code);

		OAuth2Authentication actualAuthentication = getVerificationCodeServices().consumeAuthorizationCode(code);
		assertEquals(expectedAuthentication, actualAuthentication);
	}

	@Test
	public void testConsumeRemovesCode() {
		OAuth2Authentication<UnconfirmedAuthorizationCodeAuthenticationToken, TestAuthentication> expectedAuthentication = new OAuth2Authentication<UnconfirmedAuthorizationCodeAuthenticationToken, TestAuthentication>(
				new UnconfirmedAuthorizationCodeAuthenticationToken("id", null, null, null), new TestAuthentication("test2", false));
		String code = getVerificationCodeServices().createAuthorizationCode(expectedAuthentication);
		assertNotNull(code);

		OAuth2Authentication actualAuthentication = getVerificationCodeServices().consumeAuthorizationCode(code);
		assertEquals(expectedAuthentication, actualAuthentication);

		try {
			getVerificationCodeServices().consumeAuthorizationCode(code);
			fail("Should have thrown exception");
		} catch (InvalidGrantException e) {
			// good we expected this
		}
	}

	@Test
	public void testConsumeNonExistingCode() {
		try {
			getVerificationCodeServices().consumeAuthorizationCode("doesnt exist");
			fail("Should have thrown exception");
		} catch (InvalidGrantException e) {
			// good we expected this
		}
	}

	protected static class TestAuthentication implements Authentication, Serializable {
		private String name;
		private boolean authenticated;

		public TestAuthentication(String name, boolean authenticated) {
			this.name = name;
			this.authenticated = authenticated;
		}

		public Collection<GrantedAuthority> getAuthorities() {
			return null;
		}

		public Object getCredentials() {
			return null;
		}

		public Object getDetails() {
			return null;
		}

		public Object getPrincipal() {
			return null;
		}

		public boolean isAuthenticated() {
			return authenticated;
		}

		public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
			this.authenticated = isAuthenticated;
		}

		public String getName() {
			return name;
		}

		@Override
		public boolean equals(Object o) {
			if (this == o) {
				return true;
			}
			if (o == null || getClass() != o.getClass()) {
				return false;
			}

			TestAuthentication that = (TestAuthentication) o;

			if (authenticated != that.authenticated) {
				return false;
			}
			if (name != null ? !name.equals(that.name) : that.name != null) {
				return false;
			}

			return true;
		}

		@Override
		public int hashCode() {
			int result = name != null ? name.hashCode() : 0;
			result = 31 * result + (authenticated ? 1 : 0);
			return result;
		}
	}

}
