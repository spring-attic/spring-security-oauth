package org.springframework.security.oauth2.client;

/**
 * Holder for the current OAuth2 security context.
 *
 * @author Ryan Heaton
 */
public class OAuth2SecurityContextHolder {

  private static final ThreadLocal<OAuth2SecurityContext> CURRENT_CONTEXT = new ThreadLocal<OAuth2SecurityContext>();

  public static OAuth2SecurityContext getContext() {
    return CURRENT_CONTEXT.get();
  }

  public static void setContext(OAuth2SecurityContext context) {
    CURRENT_CONTEXT.set(context);
  }
}
