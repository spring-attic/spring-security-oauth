package org.springframework.security.oauth2.common;

import java.io.Serializable;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TreeSet;

import org.codehaus.jackson.map.annotate.JsonDeserialize;
import org.codehaus.jackson.map.annotate.JsonSerialize;

/**
 * Basic access token for OAuth 2.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 * @author Rob Winch
 */
@JsonSerialize(using = OAuth2AccessTokenSerializer.class)
@JsonDeserialize(using = OAuth2AccessTokenDeserializer.class)
public class OAuth2AccessToken implements Serializable {

	private static final long serialVersionUID = 914967629530462926L;

	public static String BEARER_TYPE = "Bearer";

	public static String OAUTH2_TYPE = "OAuth2";

	/**
	 * The access token issued by the authorization server. This value is REQUIRED.
	 */
	public static String ACCESS_TOKEN = "access_token";

	/**
	 * The type of the token issued as described in <a
	 * href="http://tools.ietf.org/html/draft-ietf-oauth-v2-22#section-7.1">Section 7.1</a>. Value is case insensitive.
	 * This value is REQUIRED.
	 */
	public static String TOKEN_TYPE = "token_type";

	/**
	 * The lifetime in seconds of the access token. For example, the value "3600" denotes that the access token will
	 * expire in one hour from the time the response was generated. This value is OPTIONAL.
	 */
	public static String EXPIRES_IN = "expires_in";

	/**
	 * The refresh token which can be used to obtain new access tokens using the same authorization grant as described
	 * in <a href="http://tools.ietf.org/html/draft-ietf-oauth-v2-22#section-6">Section 6</a>. This value is OPTIONAL.
	 */
	public static String REFRESH_TOKEN = "refresh_token";

	/**
	 * The scope of the access token as described by <a
	 * href="http://tools.ietf.org/html/draft-ietf-oauth-v2-22#section-3.3">Section 3.3</a>
	 */
	public static String SCOPE = "scope";

	private final String value;

	private Date expiration;

	private String tokenType = BEARER_TYPE.toLowerCase();

	private OAuth2RefreshToken refreshToken;

	private Set<String> scope;

	/**
	 * Create an access token from the value provided.
	 */
	public OAuth2AccessToken(String value) {
		this.value = value;
	}

	@SuppressWarnings("unused")
	private OAuth2AccessToken() {
		this(null);
	}

	/**
	 * The token value.
	 * 
	 * @return The token value.
	 */
	public String getValue() {
		return value;
	}

	public int getExpiresIn() {
		return expiration != null ? Long.valueOf((expiration.getTime() - System.currentTimeMillis()) / 1000L)
				.intValue() : 0;
	}

	protected void setExpiresIn(int delta) {
		setExpiration(new Date(System.currentTimeMillis() + delta));
	}

	/**
	 * The instant the token expires.
	 * 
	 * @return The instant the token expires.
	 */
	public Date getExpiration() {
		return expiration;
	}

	/**
	 * The instant the token expires.
	 * 
	 * @param expiration The instant the token expires.
	 */
	public void setExpiration(Date expiration) {
		this.expiration = expiration;
	}

	/**
	 * Convenience method for checking expiration
	 * 
	 * @return true if the expiration is befor ethe current time
	 */
	public boolean isExpired() {
		return expiration != null && expiration.before(new Date());
	}

	/**
	 * The token type, as introduced in draft 11 of the OAuth 2 spec. The spec doesn't define (yet) that the valid token
	 * types are, but says it's required so the default will just be "undefined".
	 * 
	 * @return The token type, as introduced in draft 11 of the OAuth 2 spec.
	 */
	public String getTokenType() {
		return tokenType;
	}

	/**
	 * The token type, as introduced in draft 11 of the OAuth 2 spec.
	 * 
	 * @param tokenType The token type, as introduced in draft 11 of the OAuth 2 spec.
	 */
	public void setTokenType(String tokenType) {
		this.tokenType = tokenType;
	}

	/**
	 * The refresh token associated with the access token, if any.
	 * 
	 * @return The refresh token associated with the access token, if any.
	 */
	public OAuth2RefreshToken getRefreshToken() {
		return refreshToken;
	}

	/**
	 * The refresh token associated with the access token, if any.
	 * 
	 * @param refreshToken The refresh token associated with the access token, if any.
	 */
	public void setRefreshToken(OAuth2RefreshToken refreshToken) {
		this.refreshToken = refreshToken;
	}

	/**
	 * The scope of the token.
	 * 
	 * @return The scope of the token.
	 */
	public Set<String> getScope() {
		return scope;
	}

	/**
	 * The scope of the token.
	 * 
	 * @param scope The scope of the token.
	 */
	public void setScope(Set<String> scope) {
		this.scope = scope;
	}

	@Override
	public boolean equals(Object obj) {
		return obj != null && toString().equals(obj.toString());
	}

	@Override
	public int hashCode() {
		return toString().hashCode();
	}

	@Override
	public String toString() {
		return getValue();
	}

	public static OAuth2AccessToken valueOf(Map<String, String> tokenParams) {
		OAuth2AccessToken token = new OAuth2AccessToken(tokenParams.get(ACCESS_TOKEN));

		if (tokenParams.containsKey(EXPIRES_IN)) {
			long expiration = 0;
			try {
				expiration = Long.parseLong(String.valueOf(tokenParams.get(EXPIRES_IN)));
			} catch (NumberFormatException e) {
				// fall through...
			}
			token.setExpiration(new Date(System.currentTimeMillis() + (expiration * 1000L)));
		}

		if (tokenParams.containsKey(REFRESH_TOKEN)) {
			String refresh = tokenParams.get(REFRESH_TOKEN);
			OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(refresh);
			token.setRefreshToken(refreshToken);
		}

		if (tokenParams.containsKey(SCOPE)) {
			Set<String> scope = new TreeSet<String>();
			for (StringTokenizer tokenizer = new StringTokenizer(tokenParams.get(SCOPE), " ,"); tokenizer
					.hasMoreTokens();) {
				scope.add(tokenizer.nextToken());
			}
			token.setScope(scope);
		}

		if (tokenParams.containsKey(TOKEN_TYPE)) {
			token.setTokenType(tokenParams.get(TOKEN_TYPE));
		}

		return token;
	}

}
