package org.springframework.security.oauth2.common;

import java.util.Date;

/**
 * <p>
 * @deprecated See the <a href="https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide">OAuth 2.0 Migration Guide</a> for Spring Security 5.
 *
 * @author Ryan Heaton
 */
@Deprecated
public class DefaultExpiringOAuth2RefreshToken extends DefaultOAuth2RefreshToken implements ExpiringOAuth2RefreshToken {

	private static final long serialVersionUID = 3449554332764129719L;

	private final Date expiration;

	/**
	 * @param value
	 */
	public DefaultExpiringOAuth2RefreshToken(String value, Date expiration) {
		super(value);
		this.expiration = expiration;
	}

	/**
	 * The instant the token expires.
	 * 
	 * @return The instant the token expires.
	 */
	public Date getExpiration() {
		return expiration;
	}

}
