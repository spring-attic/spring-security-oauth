package org.springframework.security.oauth.consumer;

/**
 * Holder for the current OAuth security context.
 *
 * @author Ryan Heaton
 */
public class OAuthSecurityContextHolder {

  private static final ThreadLocal<OAuthSecurityContext> CURRENT_CONTEXT = new ThreadLocal<OAuthSecurityContext>();

  public static OAuthSecurityContext getContext() {
    return CURRENT_CONTEXT.get();
  }

  public static void setContext(OAuthSecurityContext context) {
    CURRENT_CONTEXT.set(context);
  }
}
