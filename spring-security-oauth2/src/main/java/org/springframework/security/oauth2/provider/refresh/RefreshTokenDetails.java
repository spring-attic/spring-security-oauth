package org.springframework.security.oauth2.provider.refresh;

import java.util.Set;

/**
 * Holder for refresh token details.
 *
 * @author Ryan Heaton
 */
public class RefreshTokenDetails {

	private final String refreshToken;
	private final Set<String> scope;

	public RefreshTokenDetails(String refreshToken, Set<String> scope) {
		this.refreshToken = refreshToken;
		this.scope = scope;
	}

	public String getRefreshToken() {
		return refreshToken;
	}

	public Set<String> getScope() {
		return scope;
	}
}
