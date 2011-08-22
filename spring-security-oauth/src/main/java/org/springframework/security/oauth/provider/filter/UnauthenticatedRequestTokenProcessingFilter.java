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

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth.common.OAuthCodec;
import org.springframework.security.oauth.common.OAuthConsumerParameter;
import org.springframework.security.oauth.common.OAuthProviderParameter;
import org.springframework.security.oauth.provider.ConsumerAuthentication;
import org.springframework.security.oauth.provider.ConsumerDetails;
import org.springframework.security.oauth.provider.InvalidOAuthParametersException;
import org.springframework.security.oauth.provider.token.OAuthProviderToken;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * Processing filter for handling a request for an OAuth token. The default implementation assumes a request for a new
 * unauthenticated request token. The default {@link #setFilterProcessesUrl(String) processes URL} is "/oauth_request_token".
 *
 * @author Ryan Heaton
 * @author Andrew McCall
 */
public class UnauthenticatedRequestTokenProcessingFilter extends OAuthProviderProcessingFilter {

  // The OAuth spec doesn't specify a content-type of the response.  However, it's NOT
  // "application/x-www-form-urlencoded" because the response isn't URL-encoded. Until
  // something is specified, we'll assume that it's just "text/plain".
  private String responseContentType = "text/plain;charset=utf-8";

  private boolean require10a = true;

  public UnauthenticatedRequestTokenProcessingFilter() {
    setFilterProcessesUrl("/oauth_request_token");
  }

  @Override
  protected void validateAdditionalParameters(ConsumerDetails consumerDetails, Map<String, String> oauthParams) {
    super.validateAdditionalParameters(consumerDetails, oauthParams);

    if (isRequire10a()) {
      String token = oauthParams.get(OAuthConsumerParameter.oauth_callback.toString());
      if (token == null) {
        throw new InvalidOAuthParametersException(messages.getMessage("AccessTokenProcessingFilter.missingCallback", "Missing callback."));
      }
    }
  }

  protected void onValidSignature(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException {
    //signature is verified; create the token, send the response.
    ConsumerAuthentication authentication = (ConsumerAuthentication) SecurityContextHolder.getContext().getAuthentication();
    OAuthProviderToken authToken = createOAuthToken(authentication);
    if (!authToken.getConsumerKey().equals(authentication.getConsumerDetails().getConsumerKey())) {
      throw new IllegalStateException("The consumer key associated with the created auth token is not valid for the authenticated consumer.");
    }

    String tokenValue = authToken.getValue();
    String callback = authentication.getOAuthParameters().get(OAuthConsumerParameter.oauth_callback.toString());

    StringBuilder responseValue = new StringBuilder(OAuthProviderParameter.oauth_token.toString())
      .append('=')
      .append(OAuthCodec.oauthEncode(tokenValue))
      .append('&')
      .append(OAuthProviderParameter.oauth_token_secret.toString())
      .append('=')
      .append(OAuthCodec.oauthEncode(authToken.getSecret()));
    if (callback != null) {
      responseValue.append('&')
        .append(OAuthProviderParameter.oauth_callback_confirmed.toString())
        .append("=true");
    }
    response.setContentType(getResponseContentType());
    response.getWriter().print(responseValue.toString());
    response.flushBuffer();
  }

  @Override
  protected void onNewTimestamp() throws AuthenticationException {
    //no-op. A new timestamp should be supplied for a request for a new unauthenticated request token.
  }

  /**
   * Create the OAuth token for the specified consumer key.
   *
   * @param authentication The authentication request.
   * @return The OAuth token.
   */
  protected OAuthProviderToken createOAuthToken(ConsumerAuthentication authentication) {
    return getTokenServices().createUnauthorizedRequestToken(authentication.getConsumerDetails().getConsumerKey(),
                                                             authentication.getOAuthParameters().get(OAuthConsumerParameter.oauth_callback.toString()));
  }

  /**
   * The content type of the response.
   *
   * @return The content type of the response.
   */
  public String getResponseContentType() {
    return responseContentType;
  }

  /**
   * The content type of the response.
   *
   * @param responseContentType The content type of the response.
   */
  public void setResponseContentType(String responseContentType) {
    this.responseContentType = responseContentType;
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