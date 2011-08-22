/*
 * Copyright 2009 Andrew McCall
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
package org.springframework.security.oauth.provider.filter;

import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import java.io.IOException;

import static org.springframework.security.oauth.provider.filter.UserAuthorizationProcessingFilter.CALLBACK_ATTRIBUTE;
import static org.springframework.security.oauth.provider.filter.UserAuthorizationProcessingFilter.VERIFIER_ATTRIBUTE;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Successful AuthenticationHandler that gets called when a user complete authorization of a resource.
 *
 * If the callback URL is oob, the request is handled by the SimpleUrlAuthenticationSuccessHandler using the default
 * success URL. Otherwise, the oauth_verifier and oauth_token parmeters are appended to the callback URL and the user
 * is redirected.
 *
 * @author Andrew McCall
 */
public class UserAuthorizationSuccessfulAuthenticationHandler extends SimpleUrlAuthenticationSuccessHandler {

  private static Log LOG = LogFactory.getLog(UserAuthorizationSuccessfulAuthenticationHandler.class);

  private String tokenIdParameterName = "requestToken";
  private String callbackParameterName = "callbackURL";
  private boolean require10a = true;

  public UserAuthorizationSuccessfulAuthenticationHandler() {
    super();
    setRedirectStrategy(new org.springframework.security.web.DefaultRedirectStrategy());
  }

  public UserAuthorizationSuccessfulAuthenticationHandler(String s) {
    super(s);
    setRedirectStrategy(new DefaultRedirectStrategy());
  }

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Processing successful authentication successful");
    }

    String callbackURL = (String) request.getAttribute(CALLBACK_ATTRIBUTE);
    if (callbackURL == null) {
      if (!isRequire10a()) {
        callbackURL = request.getParameter(getCallbackParameterName());
        if (callbackURL == null) {
          //if we're not requiring 1.0a, then not providing a callback url is the same as stating 'oob'
          callbackURL = "oob";
        }
      }
      else {
        throw new IllegalStateException("Callback URL was not loaded into the request. attemptAuthentication() never called?");
      }
    }

    if ("oob".equals(callbackURL)) {
      callbackURL = super.determineTargetUrl(request, response);
    }

    String requestToken = request.getParameter(getTokenParameterName());
    char appendChar = '?';
    if (callbackURL.indexOf('?') > 0) {
      appendChar = '&';
    }

    String verifier = (String) request.getAttribute(VERIFIER_ATTRIBUTE);
    String targetUrl = new StringBuilder(callbackURL).append(appendChar).append("oauth_token=").append(requestToken).append("&oauth_verifier=").append(verifier).toString();
    getRedirectStrategy().sendRedirect(request, response, targetUrl);
  }

  /**
   * The name of the request parameter that supplies the token id.
   *
   * @return The name of the request parameter that supplies the token id.
   */
  public String getTokenParameterName() {
    return tokenIdParameterName;
  }

  /**
   * The name of the request parameter that supplies the token id.
   *
   * @param tokenIdParameterName The name of the request parameter that supplies the token id.
   */
  public void setTokenIdParameterName(String tokenIdParameterName) {
    this.tokenIdParameterName = tokenIdParameterName;
  }

  /**
   * Whether to require 1.0a support.
   *
   * @return Whether to require 1.0a support.
   */
  public boolean isRequire10a() {
    return require10a;
  }

  /**
   * Whether to require 1.0a support.
   *
   * @param require10a Whether to require 1.0a support.
   */
  public void setRequire10a(boolean require10a) {
    this.require10a = require10a;
  }

  /**
   * The name of the request parameter that supplies the callback URL.
   *
   * @return The name of the request parameter that supplies the callback URL.
   */
  public String getCallbackParameterName() {
    return callbackParameterName;
  }

  /**
   * The name of the request parameter that supplies the callback URL.
   *
   * @param callbackParameterName The name of the request parameter that supplies the callback URL.
   */
  public void setCallbackParameterName(String callbackParameterName) {
    this.callbackParameterName = callbackParameterName;
  }

}
