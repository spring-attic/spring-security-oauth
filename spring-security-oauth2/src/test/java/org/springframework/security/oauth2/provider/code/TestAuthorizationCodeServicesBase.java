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

public abstract class TestAuthorizationCodeServicesBase {

	abstract AuthorizationCodeServices getAuthorizationCodeServices();

	@Test
	public void testCreateAuthorizationCode() {
		UnconfirmedAuthorizationCodeAuthenticationTokenHolder expectedAuthentication = new UnconfirmedAuthorizationCodeAuthenticationTokenHolder(
				new UnconfirmedAuthorizationCodeClientToken("id", null, null, null), new TestAuthentication(
						"test2", false));
		String code = getAuthorizationCodeServices().createAuthorizationCode(expectedAuthentication);
		assertNotNull(code);

		UnconfirmedAuthorizationCodeAuthenticationTokenHolder actualAuthentication = getAuthorizationCodeServices()
				.consumeAuthorizationCode(code);
		assertEquals(expectedAuthentication, actualAuthentication);
	}

	@Test
	public void testConsumeRemovesCode() {
		UnconfirmedAuthorizationCodeAuthenticationTokenHolder expectedAuthentication = new UnconfirmedAuthorizationCodeAuthenticationTokenHolder(
				new UnconfirmedAuthorizationCodeClientToken("id", null, null, null), new TestAuthentication(
						"test2", false));
		String code = getAuthorizationCodeServices().createAuthorizationCode(expectedAuthentication);
		assertNotNull(code);

		UnconfirmedAuthorizationCodeAuthenticationTokenHolder actualAuthentication = getAuthorizationCodeServices()
				.consumeAuthorizationCode(code);
		assertEquals(expectedAuthentication, actualAuthentication);

		try {
			getAuthorizationCodeServices().consumeAuthorizationCode(code);
			fail("Should have thrown exception");
		} catch (InvalidGrantException e) {
			// good we expected this
		}
	}

	@Test
	public void testConsumeNonExistingCode() {
		try {
			getAuthorizationCodeServices().consumeAuthorizationCode("doesnt exist");
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
