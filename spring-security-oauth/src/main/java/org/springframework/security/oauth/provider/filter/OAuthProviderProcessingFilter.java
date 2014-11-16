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

package org.springframework.security.oauth.provider.filter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth.common.OAuthConsumerParameter;
import org.springframework.security.oauth.common.OAuthException;
import org.springframework.security.oauth.common.signature.*;
import org.springframework.security.oauth.provider.ConsumerAuthentication;
import org.springframework.security.oauth.provider.ConsumerCredentials;
import org.springframework.security.oauth.provider.ConsumerDetails;
import org.springframework.security.oauth.provider.ConsumerDetailsService;
import org.springframework.security.oauth.provider.InvalidOAuthParametersException;
import org.springframework.security.oauth.provider.OAuthAuthenticationDetails;
import org.springframework.security.oauth.provider.OAuthProcessingFilterEntryPoint;
import org.springframework.security.oauth.provider.OAuthProviderSupport;
import org.springframework.security.oauth.provider.OAuthVersionUnsupportedException;
import org.springframework.security.oauth.provider.nonce.ExpiringTimestampNonceServices;
import org.springframework.security.oauth.provider.nonce.OAuthNonceServices;
import org.springframework.security.oauth.provider.token.OAuthProviderToken;
import org.springframework.security.oauth.provider.token.OAuthProviderTokenServices;
import org.springframework.util.Assert;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * OAuth processing filter. This filter should be applied to requests for OAuth protected resources (see OAuth Core 1.0).
 *
 * @author Ryan Heaton
 */
public abstract class OAuthProviderProcessingFilter implements Filter, InitializingBean, MessageSourceAware {

  /**
   * Attribute for indicating that OAuth processing has already occurred.
   */
  public static final String OAUTH_PROCESSING_HANDLED = "org.springframework.security.oauth.provider.OAuthProviderProcessingFilter#SKIP_PROCESSING";

  private final Log log = LogFactory.getLog(getClass());
  private final List<String> allowedMethods = new ArrayList<String>(Arrays.asList("GET", "POST"));
  private OAuthProcessingFilterEntryPoint authenticationEntryPoint = new OAuthProcessingFilterEntryPoint();
  protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
  private String filterProcessesUrl = "/oauth_filter";
  private OAuthProviderSupport providerSupport = new CoreOAuthProviderSupport();
  private OAuthSignatureMethodFactory signatureMethodFactory = new CoreOAuthSignatureMethodFactory();
  private OAuthNonceServices nonceServices = new ExpiringTimestampNonceServices();
  private boolean ignoreMissingCredentials = false;
  private OAuthProviderTokenServices tokenServices;

  private ConsumerDetailsService consumerDetailsService;

  public void afterPropertiesSet() throws Exception {
    Assert.notNull(consumerDetailsService, "A consumer details service is required.");
    Assert.notNull(tokenServices, "Token services are required.");
  }

  public void init(FilterConfig ignored) throws ServletException {
  }

  public void destroy() {
  }

  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) servletRequest;
    HttpServletResponse response = (HttpServletResponse) servletResponse;

    if (!skipProcessing(request)) {
      if (requiresAuthentication(request, response, chain)) {
        if (!allowMethod(request.getMethod().toUpperCase())) {
          if (log.isDebugEnabled()) {
            log.debug("Method " + request.getMethod() + " not supported.");
          }

          response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
          return;
        }

        try {
          Map<String, String> oauthParams = getProviderSupport().parseParameters(request);

          if (parametersAreAdequate(oauthParams)) {

            if (log.isDebugEnabled()) {
              StringBuilder builder = new StringBuilder("OAuth parameters parsed: ");
              for (String param : oauthParams.keySet()) {
                builder.append(param).append('=').append(oauthParams.get(param)).append(' ');
              }
              log.debug(builder.toString());
            }

            String consumerKey = oauthParams.get(OAuthConsumerParameter.oauth_consumer_key.toString());
            if (consumerKey == null) {
              throw new InvalidOAuthParametersException(messages.getMessage("OAuthProcessingFilter.missingConsumerKey", "Missing consumer key."));
            }

            //load the consumer details.
            ConsumerDetails consumerDetails = getConsumerDetailsService().loadConsumerByConsumerKey(consumerKey);
            if (log.isDebugEnabled()) {
              log.debug("Consumer details loaded for " + consumerKey + ": " + consumerDetails);
            }

            //validate the parameters for the consumer.
            validateOAuthParams(consumerDetails, oauthParams);
            if (log.isDebugEnabled()) {
              log.debug("Parameters validated.");
            }

            //extract the credentials.
            String token = oauthParams.get(OAuthConsumerParameter.oauth_token.toString());
            String signatureMethod = oauthParams.get(OAuthConsumerParameter.oauth_signature_method.toString());
            String signature = oauthParams.get(OAuthConsumerParameter.oauth_signature.toString());
            String signatureBaseString = getProviderSupport().getSignatureBaseString(request);
            ConsumerCredentials credentials = new ConsumerCredentials(consumerKey, signature, signatureMethod, signatureBaseString, token);

            //create an authentication request.
            ConsumerAuthentication authentication = new ConsumerAuthentication(consumerDetails, credentials, oauthParams);
            authentication.setDetails(createDetails(request, consumerDetails));

            Authentication previousAuthentication = SecurityContextHolder.getContext().getAuthentication();
            try {
              //set the authentication request (unauthenticated) into the context.
              SecurityContextHolder.getContext().setAuthentication(authentication);

              //validate the signature.
              validateSignature(authentication);

              //mark the authentication request as validated.
              authentication.setSignatureValidated(true);

              //mark that processing has been handled.
              request.setAttribute(OAUTH_PROCESSING_HANDLED, Boolean.TRUE);

              if (log.isDebugEnabled()) {
                log.debug("Signature validated.");
              }

              //go.
              onValidSignature(request, response, chain);
            }
            finally {
              //clear out the consumer authentication to make sure it doesn't get cached.
              resetPreviousAuthentication(previousAuthentication);
            }
          }
          else if (!isIgnoreInadequateCredentials()) {
            throw new InvalidOAuthParametersException(messages.getMessage("OAuthProcessingFilter.missingCredentials", "Inadequate OAuth consumer credentials."));
          }
          else {
            if (log.isDebugEnabled()) {
              log.debug("Supplied OAuth parameters are inadequate. Ignoring.");
            }
            chain.doFilter(request, response);
          }
        }
        catch (AuthenticationException ae) {
          fail(request, response, ae);
        }
        catch (ServletException e) {
          if (e.getRootCause() instanceof AuthenticationException) {
            fail(request, response, (AuthenticationException) e.getRootCause());
          }
          else {
            throw e;
          }
        }
      }
      else {
        if (log.isDebugEnabled()) {
          log.debug("Request does not require authentication.  OAuth processing skipped.");
        }

        chain.doFilter(servletRequest, servletResponse);
      }
    }
    else {
      if (log.isDebugEnabled()) {
        log.debug("Processing explicitly skipped.");
      }

      chain.doFilter(servletRequest, servletResponse);
    }
  }

  /**
   * By default, OAuth parameters are adequate if a consumer key is present.
   *
   * @param oauthParams The oauth params.
   * @return Whether the parsed parameters are adequate.
   */
  protected boolean parametersAreAdequate(Map<String, String> oauthParams) {
    return oauthParams.containsKey(OAuthConsumerParameter.oauth_consumer_key.toString());
  }

  protected void resetPreviousAuthentication(Authentication previousAuthentication) {
    SecurityContextHolder.getContext().setAuthentication(previousAuthentication);
  }

  /**
   * Create the details for the authentication request.
   *
   * @param request The request.
   * @param consumerDetails The consumer details.
   * @return The authentication details.
   */
  protected Object createDetails(HttpServletRequest request, ConsumerDetails consumerDetails) {
    return new OAuthAuthenticationDetails(request, consumerDetails);
  }

  /**
   * Whether to allow the specified HTTP method.
   *
   * @param method The HTTP method to check for allowing.
   * @return Whether to allow the specified method.
   */
  protected boolean allowMethod(String method) {
    return allowedMethods.contains(method);
  }

  /**
   * Validate the signature of the request given the authentication request.
   *
   * @param authentication The authentication request.
   */
  protected void validateSignature(ConsumerAuthentication authentication) throws AuthenticationException {
    SignatureSecret secret = authentication.getConsumerDetails().getSignatureSecret();
    String token = authentication.getConsumerCredentials().getToken();
    OAuthProviderToken authToken = null;
    if (token != null && !"".equals(token)) {
      authToken = getTokenServices().getToken(token);
    }

    String signatureMethod = authentication.getConsumerCredentials().getSignatureMethod();
    OAuthSignatureMethod method;
    try {
      method = getSignatureMethodFactory().getSignatureMethod(signatureMethod, secret, authToken != null ? authToken.getSecret() : null);
    }
    catch (UnsupportedSignatureMethodException e) {
      throw new OAuthException(e.getMessage(), e);
    }

    String signatureBaseString = authentication.getConsumerCredentials().getSignatureBaseString();
    String signature = authentication.getConsumerCredentials().getSignature();
    if (log.isDebugEnabled()) {
      log.debug("Verifying signature " + signature + " for signature base string " + signatureBaseString + " with method " + method.getName() + ".");
    }
    method.verify(signatureBaseString, signature);
  }

  /**
   * Logic executed on valid signature. The security context can be assumed to hold a verified, authenticated
   * {@link org.springframework.security.oauth.provider.ConsumerAuthentication}
   *
   * Default implementation continues the chain.
   *
   * @param request  The request.
   * @param response The response
   * @param chain    The filter chain.
   */
  protected abstract void onValidSignature(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException;

  /**
   * Validates the OAuth parameters for the given consumer. Base implementation validates only those parameters
   * that are required for all OAuth requests. This includes the nonce and timestamp, but not the signature.
   *
   * @param consumerDetails The consumer details.
   * @param oauthParams     The OAuth parameters to validate.
   * @throws InvalidOAuthParametersException If the OAuth parameters are invalid.
   */
  protected void validateOAuthParams(ConsumerDetails consumerDetails, Map<String, String> oauthParams) throws InvalidOAuthParametersException {
    String version = oauthParams.get(OAuthConsumerParameter.oauth_version.toString());
    if ((version != null) && (!"1.0".equals(version))) {
      throw new OAuthVersionUnsupportedException("Unsupported OAuth version: " + version);
    }

    String realm = oauthParams.get("realm");
    realm = realm == null || "".equals(realm) ? null : realm;
    if ((realm != null) && (!realm.equals(this.authenticationEntryPoint.getRealmName()))) {
      throw new InvalidOAuthParametersException(messages.getMessage("OAuthProcessingFilter.incorrectRealm",
                                                                    new Object[]{realm, this.getAuthenticationEntryPoint().getRealmName()},
                                                                    "Response realm name '{0}' does not match system realm name of '{1}'"));
    }

    String signatureMethod = oauthParams.get(OAuthConsumerParameter.oauth_signature_method.toString());
    if (signatureMethod == null) {
      throw new InvalidOAuthParametersException(messages.getMessage("OAuthProcessingFilter.missingSignatureMethod", "Missing signature method."));
    }

    String signature = oauthParams.get(OAuthConsumerParameter.oauth_signature.toString());
    if (signature == null) {
      throw new InvalidOAuthParametersException(messages.getMessage("OAuthProcessingFilter.missingSignature", "Missing signature."));
    }

    String timestamp = oauthParams.get(OAuthConsumerParameter.oauth_timestamp.toString());
    if (timestamp == null) {
      throw new InvalidOAuthParametersException(messages.getMessage("OAuthProcessingFilter.missingTimestamp", "Missing timestamp."));
    }

    String nonce = oauthParams.get(OAuthConsumerParameter.oauth_nonce.toString());
    if (nonce == null) {
      throw new InvalidOAuthParametersException(messages.getMessage("OAuthProcessingFilter.missingNonce", "Missing nonce."));
    }

    try {
      getNonceServices().validateNonce(consumerDetails, Long.parseLong(timestamp), nonce);
    }
    catch (NumberFormatException e) {
      throw new InvalidOAuthParametersException(messages.getMessage("OAuthProcessingFilter.invalidTimestamp", new Object[]{timestamp}, "Timestamp must be a positive integer. Invalid value: {0}"));
    }

    validateAdditionalParameters(consumerDetails, oauthParams);
  }

  /**
   * Do any additional validation checks for the specified oauth params.  Default implementation is a no-op.
   *
   * @param consumerDetails The consumer details.
   * @param oauthParams The params.
   */
  protected void validateAdditionalParameters(ConsumerDetails consumerDetails, Map<String, String> oauthParams) {
  }

  /**
   * Logic to be performed on a new timestamp.  The default behavior expects that the timestamp should not be new.
   *
   * @throws org.springframework.security.core.AuthenticationException
   *          If the timestamp shouldn't be new.
   */
  protected void onNewTimestamp() throws AuthenticationException {
    throw new InvalidOAuthParametersException(messages.getMessage("OAuthProcessingFilter.timestampNotNew", "A new timestamp should not be used in a request for an access token."));
  }

  /**
   * Common logic for OAuth failed.
   *
   * @param request  The request.
   * @param response The response.
   * @param failure  The failure.
   * @throws IOException thrown when there's an underlying IO exception
   * @throws ServletException thrown in the case of an underlying Servlet exception 
   */
  protected void fail(HttpServletRequest request, HttpServletResponse response, AuthenticationException failure) throws IOException, ServletException {
    SecurityContextHolder.getContext().setAuthentication(null);

    if (log.isDebugEnabled()) {
      log.debug(failure);
    }

    authenticationEntryPoint.commence(request, response, failure);
  }

  /**
   * Whether this filter is configured to process the specified request.
   *
   * @param request     The request.
   * @param response    The response
   * @param filterChain The filter chain
   * @return Whether this filter is configured to process the specified request.
   */
  protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {
    //copied from org.springframework.security.ui.AbstractProcessingFilter.requiresAuthentication
    String uri = request.getRequestURI();
    int pathParamIndex = uri.indexOf(';');

    if (pathParamIndex > 0) {
      // strip everything after the first semi-colon
      uri = uri.substring(0, pathParamIndex);
    }

    if ("".equals(request.getContextPath())) {
      return uri.endsWith(filterProcessesUrl);
    }

    boolean match = uri.endsWith(request.getContextPath() + filterProcessesUrl);
    if (log.isDebugEnabled()) {
      log.debug(uri + (match ? " matches " : " does not match ") + filterProcessesUrl);
    }
    return match;
  }

  /**
   * Whether to skip processing for the specified request.
   *
   * @param request The request.
   * @return Whether to skip processing.
   */
  protected boolean skipProcessing(HttpServletRequest request) {
    return ((request.getAttribute(OAUTH_PROCESSING_HANDLED) != null) && (Boolean.TRUE.equals(request.getAttribute(OAUTH_PROCESSING_HANDLED))));
  }

  /**
   * The authentication entry point.
   *
   * @return The authentication entry point.
   */
  public OAuthProcessingFilterEntryPoint getAuthenticationEntryPoint() {
    return authenticationEntryPoint;
  }

  /**
   * The authentication entry point.
   *
   * @param authenticationEntryPoint The authentication entry point.
   */
  @Autowired (required = false)
  public void setAuthenticationEntryPoint(OAuthProcessingFilterEntryPoint authenticationEntryPoint) {
    this.authenticationEntryPoint = authenticationEntryPoint;
  }

  /**
   * The consumer details service.
   *
   * @return The consumer details service.
   */
  public ConsumerDetailsService getConsumerDetailsService() {
    return consumerDetailsService;
  }

  /**
   * The consumer details service.
   *
   * @param consumerDetailsService The consumer details service.
   */
  @Autowired
  public void setConsumerDetailsService(ConsumerDetailsService consumerDetailsService) {
    this.consumerDetailsService = consumerDetailsService;
  }

  /**
   * The nonce services.
   *
   * @return The nonce services.
   */
  public OAuthNonceServices getNonceServices() {
    return nonceServices;
  }

  /**
   * The nonce services.
   *
   * @param nonceServices The nonce services.
   */
  @Autowired (required = false)
  public void setNonceServices(OAuthNonceServices nonceServices) {
    this.nonceServices = nonceServices;
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
   * The URL for which this filter will be applied.
   *
   * @return The URL for which this filter will be applied.
   */
  public String getFilterProcessesUrl() {
    return filterProcessesUrl;
  }

  /**
   * The URL for which this filter will be applied.
   *
   * @param filterProcessesUrl The URL for which this filter will be applied.
   */
  public void setFilterProcessesUrl(String filterProcessesUrl) {
    this.filterProcessesUrl = filterProcessesUrl;
  }

  /**
   * Set the message source.
   *
   * @param messageSource The message source.
   */
  public void setMessageSource(MessageSource messageSource) {
    this.messages = new MessageSourceAccessor(messageSource);
  }

  /**
   * The OAuth provider support.
   *
   * @return The OAuth provider support.
   */
  public OAuthProviderSupport getProviderSupport() {
    return providerSupport;
  }

  /**
   * The OAuth provider support.
   *
   * @param providerSupport The OAuth provider support.
   */
  @Autowired (required = false)
  public void setProviderSupport(OAuthProviderSupport providerSupport) {
    this.providerSupport = providerSupport;
  }

  /**
   * The OAuth signature method factory.
   *
   * @return The OAuth signature method factory.
   */
  public OAuthSignatureMethodFactory getSignatureMethodFactory() {
    return signatureMethodFactory;
  }

  /**
   * The OAuth signature method factory.
   *
   * @param signatureMethodFactory The OAuth signature method factory.
   */
  @Autowired (required = false)
  public void setSignatureMethodFactory(OAuthSignatureMethodFactory signatureMethodFactory) {
    this.signatureMethodFactory = signatureMethodFactory;
  }

  /**
   * Whether to ignore missing OAuth credentials.
   *
   * @return Whether to ignore missing OAuth credentials.
   */
  public boolean isIgnoreInadequateCredentials() {
    return ignoreMissingCredentials;
  }

  /**
   * Whether to ignore missing OAuth credentials.
   *
   * @param ignoreMissingCredentials Whether to ignore missing OAuth credentials.
   */
  public void setIgnoreMissingCredentials(boolean ignoreMissingCredentials) {
    this.ignoreMissingCredentials = ignoreMissingCredentials;
  }

  /**
   * The allowed set of HTTP methods.
   *
   * @param allowedMethods The allowed set of methods.
   */
  public void setAllowedMethods(List<String> allowedMethods) {
    this.allowedMethods.clear();
    if (allowedMethods != null) {
      for (String allowedMethod : allowedMethods) {
        this.allowedMethods.add(allowedMethod.toUpperCase());
      }
    }
  }
}
