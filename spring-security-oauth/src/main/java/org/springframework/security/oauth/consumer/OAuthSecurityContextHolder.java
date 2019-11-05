package org.springframework.security.oauth.consumer;

/**
 * Holder for the current OAuth security context.
 *
 * <p>
 * @deprecated The OAuth 1.0 Protocol <a href="https://tools.ietf.org/html/rfc5849">RFC 5849</a> is obsoleted by the OAuth 2.0 Authorization Framework <a href="https://tools.ietf.org/html/rfc6749">RFC 6749</a>.
 *
 * @author Ryan Heaton
 */
@Deprecated
public class OAuthSecurityContextHolder {

  private static final ThreadLocal<OAuthSecurityContext> CURRENT_CONTEXT = new ThreadLocal<OAuthSecurityContext>();

  public static OAuthSecurityContext getContext() {
    return CURRENT_CONTEXT.get();
  }

  public static void setContext(OAuthSecurityContext context) {
    CURRENT_CONTEXT.set(context);
  }
}
