/*
 * Copyright 2008-2009 Web Cohesion, Andrew McCall
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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth.provider.InvalidOAuthParametersException;
import org.springframework.security.oauth.provider.token.InvalidOAuthTokenException;
import org.springframework.security.oauth.provider.token.OAuthProviderToken;
import org.springframework.security.oauth.provider.token.OAuthProviderTokenServices;
import org.springframework.security.oauth.provider.verifier.OAuthVerifierServices;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Processing filter for handling a request to authenticate an OAuth request token. The default {@link #setFilterProcessesUrl(String) processes URL}
 * is "/oauth_authenticate_token".
 *
 * This filter looks for one request parameter for the token id that is being authorized. The
 * default name of the paramaters is "requestToken", but this can be configured.
 *
 * @author Ryan Heaton
 * @author Andrew McCall
 */
public class UserAuthorizationProcessingFilter extends AbstractAuthenticationProcessingFilter {

  protected static final String CALLBACK_ATTRIBUTE = UserAuthorizationProcessingFilter.class.getName() + "#CALLBACK";
  protected static final String VERIFIER_ATTRIBUTE = UserAuthorizationProcessingFilter.class.getName() + "#VERIFIER";

  private OAuthProviderTokenServices tokenServices;
  private String tokenIdParameterName = "requestToken";
  private OAuthVerifierServices verifierServices;
  private boolean require10a = true;

  public UserAuthorizationProcessingFilter() {
    super("/oauth_authenticate_token");
  }

  public UserAuthorizationProcessingFilter(String defaultProcessesUrl) {
    super(defaultProcessesUrl);
  }

  @Override
  public void afterPropertiesSet() {
    // call super.
    super.afterPropertiesSet();
    Assert.notNull(getTokenServices(), "A token services must be provided.");
    Assert.notNull(getVerifierServices(), "Verifier services are required.");
  }

  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
    String requestToken = request.getParameter(getTokenParameterName());
    if (requestToken == null) {
      throw new InvalidOAuthParametersException("An OAuth token id is required.");
    }

    OAuthProviderToken token = getTokenServices().getToken(requestToken);
    if (token == null) {
      throw new InvalidOAuthTokenException("No callback value has been provided for request token " + requestToken + ".");
    }

    String callbackURL = token.getCallbackUrl();
    if (isRequire10a() && callbackURL == null) {
      throw new InvalidOAuthTokenException("No callback value has been provided for request token " + requestToken + ".");
    }

    if (callbackURL != null) {
      request.setAttribute(CALLBACK_ATTRIBUTE, callbackURL);
    }

    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication == null || !authentication.isAuthenticated()) {
      throw new InsufficientAuthenticationException("User must be authenticated before authorizing a request token.");
    }
    String verifier = getVerifierServices().createVerifier();
    request.setAttribute(VERIFIER_ATTRIBUTE, verifier);
    getTokenServices().authorizeRequestToken(requestToken, verifier, authentication);
    return authentication;
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
   * Get the OAuth token services.
   *
   * @return The OAuth token services.
   */
  public OAuthProviderTokenServices getTokenServices() {
    return tokenServices;
  }

  /**
   * The OAuth token services.
   *
   * @param tokenServices The OAuth token services.
   */
  @Autowired
  public void setTokenServices(OAuthProviderTokenServices tokenServices) {
    this.tokenServices = tokenServices;
  }

  /**
   * The verifier services to use.
   *
   * @return The verifier services to use.
   */
  public OAuthVerifierServices getVerifierServices() {
    return verifierServices;
  }

  /**
   * The verifier services to use.
   *
   * @param verifierServices The verifier services to use.
   */
  @Autowired
  public void setVerifierServices(OAuthVerifierServices verifierServices) {
    this.verifierServices = verifierServices;
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

}
