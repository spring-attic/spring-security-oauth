package org.springframework.security.oauth2.client.context;

/**
 * Holder for the current OAuth2 security context.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class OAuth2ClientContextHolder {

	private static final ThreadLocal<OAuth2ClientContext> CURRENT_CONTEXT = new ThreadLocal<OAuth2ClientContext>();

	public static OAuth2ClientContext getContext() {
		return CURRENT_CONTEXT.get();
	}

	public static void setContext(OAuth2ClientContext context) {
		if (context != null) {
			CURRENT_CONTEXT.set(context);
		} else {
			clearContext();
		}
	}

	public static void clearContext() {
		CURRENT_CONTEXT.remove();
	}

}
