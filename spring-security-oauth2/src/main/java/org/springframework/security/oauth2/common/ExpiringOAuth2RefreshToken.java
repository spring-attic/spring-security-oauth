package org.springframework.security.oauth2.common;

import java.util.Date;

/**
 * @author Ryan Heaton
 */
public class ExpiringOAuth2RefreshToken extends OAuth2RefreshToken {

	private static final long serialVersionUID = 3449554332764129719L;

	private final Date expiration;

	/**
	 * @param value
	 */
	public ExpiringOAuth2RefreshToken(String value, Date expiration) {
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
