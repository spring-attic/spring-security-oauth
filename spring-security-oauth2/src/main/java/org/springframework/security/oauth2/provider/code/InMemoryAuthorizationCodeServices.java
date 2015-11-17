package org.springframework.security.oauth2.provider.code;

import java.util.Iterator;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * Implementation of authorization code services that stores the codes and authentication in memory.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class InMemoryAuthorizationCodeServices extends RandomValueAuthorizationCodeServices {
	/**
	 *  From RFC6749: A maximum authorization code lifetime of 10 minutes is RECOMMENDED
	 *
	 *  @see <a href="https://tools.ietf.org/html/rfc6749#section-4.1.2">RFC6749 4.1.2.  Authorization Response</a>
	 */
	private static final int DEFAULT_CODE_LIFETIME_SECONDS = 10*60;

	private int codeLiftetimeSeconds = DEFAULT_CODE_LIFETIME_SECONDS;

	protected final ConcurrentHashMap<String, ExpiringOAuth2Authentication> authorizationCodeStore = new ConcurrentHashMap<String, ExpiringOAuth2Authentication>();

	@Override
	protected void store(String code, OAuth2Authentication authentication) {
		this.authorizationCodeStore.put(code, new ExpiringOAuth2Authentication(System.currentTimeMillis(),
			authentication));
	}

	@Override
	public OAuth2Authentication remove(String code) {
		removeExpired();
		ExpiringOAuth2Authentication expiringOAuth2Authentication = this.authorizationCodeStore.remove(code);
		return expiringOAuth2Authentication == null ? null : expiringOAuth2Authentication.authentication;
	}

	private void removeExpired() {
		synchronized (authorizationCodeStore) {
			long expirationThreshold = System.currentTimeMillis() - codeLiftetimeSeconds;
			for (Iterator<ExpiringOAuth2Authentication> iterator = authorizationCodeStore.values().iterator(); iterator.hasNext(); ) {
				if (iterator.next().createdTimestamp < expirationThreshold) {
					iterator.remove();
				}
			}
		}
	}

	private static class ExpiringOAuth2Authentication {
		private final long createdTimestamp;
		private final OAuth2Authentication authentication;

		private ExpiringOAuth2Authentication(final long createdTimestamp, final OAuth2Authentication authentication) {
			this.createdTimestamp = createdTimestamp;
			this.authentication = authentication;
		}
	}

	public void setCodeLiftetimeSeconds(int codeLiftetimeSeconds) {
		this.codeLiftetimeSeconds = codeLiftetimeSeconds;
	}
}
