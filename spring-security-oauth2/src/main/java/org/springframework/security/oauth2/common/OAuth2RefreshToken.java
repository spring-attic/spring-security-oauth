package org.springframework.security.oauth2.common;

import java.io.Serializable;

import org.codehaus.jackson.annotate.JsonCreator;
import org.codehaus.jackson.annotate.JsonValue;

/**
 * An OAuth 2 refresh token.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class OAuth2RefreshToken implements Serializable {

	private static final long serialVersionUID = 8349970621900575838L;

	private final String value;

	/**
	 * Create a new refresh token.
	 */
	@JsonCreator
	public OAuth2RefreshToken(String value) {
		this.value = value;
	}

	/**
	 * The value of the token.
	 * 
	 * @return The value of the token.
	 */
	@JsonValue
	public String getValue() {
		return value;
	}

	@Override
	public String toString() {
		return getValue();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (!(o instanceof OAuth2RefreshToken)) {
			return false;
		}

		OAuth2RefreshToken that = (OAuth2RefreshToken) o;

		if (value != null ? !value.equals(that.value) : that.value != null) {
			return false;
		}

		return true;
	}

	@Override
	public int hashCode() {
		return value != null ? value.hashCode() : 0;
	}
}
