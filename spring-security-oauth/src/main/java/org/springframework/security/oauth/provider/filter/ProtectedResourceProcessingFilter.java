/*
 * Copyright 2008-2009 Web Cohesion
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

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth.provider.ConsumerAuthentication;
import org.springframework.security.oauth.provider.DefaultAuthenticationHandler;
import org.springframework.security.oauth.provider.ExtraTrustConsumerDetails;
import org.springframework.security.oauth.provider.InvalidOAuthParametersException;
import org.springframework.security.oauth.provider.OAuthAuthenticationHandler;
import org.springframework.security.oauth.provider.token.OAuthAccessProviderToken;
import org.springframework.security.oauth.provider.token.OAuthProviderToken;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Processing filter for requests to protected resources. This filter attempts to load the OAuth authentication
 * request into the security context using a presented access token.  Default behavior of this filter allows
 * the request to continue even if OAuth credentials are not presented (allowing another filter to potentially
 * load a different authentication request into the security context). If the protected resource is available
 * ONLY via OAuth access token, set <code>ignoreMissingCredentials</code> to <code>false</code>. 
 *
 * @author Ryan Heaton
 * @author Andrew McCall
 */
public class ProtectedResourceProcessingFilter extends OAuthProviderProcessingFilter {

  private boolean allowAllMethods = true;
  private OAuthAuthenticationHandler authHandler = new DefaultAuthenticationHandler();

  public ProtectedResourceProcessingFilter() {
    //we're going to ignore missing credentials by default.  This is to allow a chance for the resource to
    //be accessed by some other means of authentication.
    setIgnoreMissingCredentials(true);
  }

  @Override
  protected boolean allowMethod(String method) {
    return allowAllMethods || super.allowMethod(method);
  }

  protected void onValidSignature(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
    ConsumerAuthentication authentication = (ConsumerAuthentication) SecurityContextHolder.getContext().getAuthentication();
    String token = authentication.getConsumerCredentials().getToken();
    OAuthAccessProviderToken accessToken = null;
    if (StringUtils.hasText(token)) {
      OAuthProviderToken authToken = getTokenServices().getToken(token);
      if (authToken == null) {
        throw new AccessDeniedException("Invalid access token.");
      }
      else if (!authToken.isAccessToken()) {
        throw new AccessDeniedException("Token should be an access token.");
      }
      else if (authToken instanceof OAuthAccessProviderToken) {
        accessToken = (OAuthAccessProviderToken) authToken;
      }
    }
    else if ((!(authentication.getConsumerDetails() instanceof ExtraTrustConsumerDetails)) ||
      ((ExtraTrustConsumerDetails)authentication.getConsumerDetails()).isRequiredToObtainAuthenticatedToken()) {
      throw new InvalidOAuthParametersException(messages.getMessage("ProtectedResourceProcessingFilter.missingToken", "Missing auth token."));
    }

    Authentication userAuthentication = authHandler.createAuthentication(request, authentication, accessToken);
    SecurityContextHolder.getContext().setAuthentication(userAuthentication);

    chain.doFilter(request, response);
  }

  @Override
  protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {
    return true;
  }

  @Override
  public void setFilterProcessesUrl(String filterProcessesUrl) {
    throw new UnsupportedOperationException("The OAuth protected resource processing filter doesn't support a filter processes URL.");
  }

  /**
   * Whether to allow all methods.
   *
   * @return Whether to allow all methods.
   */
  public boolean isAllowAllMethods() {
    return allowAllMethods;
  }

  /**
   * Whether to allow all methods.
   *
   * @param allowAllMethods Whether to allow all methods.
   */
  public void setAllowAllMethods(boolean allowAllMethods) {
    this.allowAllMethods = allowAllMethods;
  }

  /**
   * The authentication handler.
   *
   * @return The authentication handler.
   */
  public OAuthAuthenticationHandler getAuthHandler() {
    return authHandler;
  }

  /**
   * The authentication handler.
   *
   * @param authHandler The authentication handler.
   */
  public void setAuthHandler(OAuthAuthenticationHandler authHandler) {
    this.authHandler = authHandler;
  }
}
