/*
 * Copyright 2008 Web Cohesion
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth.consumer.token;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth.consumer.OAuthConsumerToken;
import org.springframework.security.oauth.consumer.OAuthSecurityContext;
import org.springframework.security.oauth.consumer.OAuthSecurityContextHolder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * Stores the tokens in an HTTP session.
 *
 * @author Ryan Heaton
 */
public class HttpSessionBasedTokenServices implements OAuthConsumerTokenServices {

  public static final String KEY_PREFIX = "OAUTH_TOKEN";


  public OAuthConsumerToken getToken(String resourceId) throws AuthenticationException {
    HttpSession session = getSession();
    OAuthConsumerToken consumerToken = (OAuthConsumerToken) session.getAttribute(KEY_PREFIX + "#" + resourceId);
    if (consumerToken != null) {
      Long expiration = (Long) session.getAttribute(KEY_PREFIX + "#" + resourceId + "#EXPIRATION");
      if (expiration != null && (System.currentTimeMillis() > expiration)) {
        //token expired; remove it
        removeToken(resourceId);
        consumerToken = null;
      }
    }

    return consumerToken;
  }

  public void storeToken(String resourceId, OAuthConsumerToken token) {
    HttpSession session = getSession();
    session.setAttribute(KEY_PREFIX + "#" + resourceId, token);

    //adding support for oauth session extension (http://oauth.googlecode.com/svn/spec/ext/session/1.0/drafts/1/spec.html)
    Long expiration = null;
    String expiresInValue = token.getAdditionalParameters() != null ? token.getAdditionalParameters().get("oauth_expires_in") : null;
    if (expiresInValue != null) {
      try {
        expiration = System.currentTimeMillis() + (Integer.parseInt(expiresInValue) * 1000);
      }
      catch (NumberFormatException e) {
        //fall through.
      }
    }

    if (expiration != null) {
      session.setAttribute(KEY_PREFIX + "#" + resourceId + "#EXPIRATION", expiration);
    }
  }

  public void removeToken(String resourceId) {
    getSession().removeAttribute(KEY_PREFIX + "#" + resourceId);
  }

  protected HttpSession getSession() {
    OAuthSecurityContext context = OAuthSecurityContextHolder.getContext();
    if (context == null) {
      throw new IllegalStateException("A security context must be established.");
    }

    HttpServletRequest request;
    try {
      request = (HttpServletRequest) context.getDetails();
    }
    catch (ClassCastException e) {
      throw new IllegalStateException("The security context must have the HTTP servlet request as its details.");
    }

    if (request == null) {
      throw new IllegalStateException("The security context must have the HTTP servlet request as its details.");
    }

    HttpSession session = request.getSession(true);
    if (session == null) {
      throw new IllegalStateException("Unable to create a session in which to store the tokens.");
    }

    return session;
  }

}
