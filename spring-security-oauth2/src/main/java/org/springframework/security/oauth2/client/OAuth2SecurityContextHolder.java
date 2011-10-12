package org.springframework.security.oauth2.client;

/**
 * Holder for the current OAuth2 security context.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class OAuth2SecurityContextHolder {

	private static final ThreadLocal<OAuth2SecurityContext> CURRENT_CONTEXT = new ThreadLocal<OAuth2SecurityContext>();

	public static OAuth2SecurityContext getContext() {
		return CURRENT_CONTEXT.get();
	}

	public static void setContext(OAuth2SecurityContext context) {
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
