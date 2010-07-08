package org.springframework.security.oauth2.provider.webserver;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.oauth2.provider.ClientAuthenticationToken;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * Request cache for OAuth2 authorization.
 *
 * @author Ryan Heaton
 */
public class DefaultClientAuthenticationCache implements ClientAuthenticationCache {

  public static final String SAVED_AUTH_KEY = "org.springframework.security.oauth2.provider.webserver.DefaultClientAuthenticationCache#SAVED_AUTH";

  protected final Log logger = LogFactory.getLog(this.getClass());

  /**
   * Default implementation stores the authentication in a session.
   *
   * @param auth The authentication.
   * @param request The request.
   * @param response The response.
   */
  public void saveAuthentication(ClientAuthenticationToken auth, HttpServletRequest request, HttpServletResponse response) {
    if (request.getSession(false) != null) {
      request.getSession().setAttribute(SAVED_AUTH_KEY, auth);
      if (logger.isDebugEnabled()) {
        logger.debug("Client authentication added to the session: " + auth);
      }
    }
    else {
      logger.warn("Unable to save client authentication because the request doesn't have a session!");
    }
  }

  public void updateAuthentication(ClientAuthenticationToken auth, HttpServletRequest request, HttpServletResponse response) {
    saveAuthentication(auth, request, response);
  }

  public ClientAuthenticationToken getAuthentication(HttpServletRequest request, HttpServletResponse response) {
    HttpSession session = request.getSession(false);

    if (session != null) {
      return (ClientAuthenticationToken) session.getAttribute(SAVED_AUTH_KEY);
    }

    return null;
  }

  public void removeAuthentication(HttpServletRequest request, HttpServletResponse response) {
    HttpSession session = request.getSession(false);

    if (session != null) {
      logger.debug("Removing client authentication from session if present");
      session.removeAttribute(SAVED_AUTH_KEY);
    }
  }

}