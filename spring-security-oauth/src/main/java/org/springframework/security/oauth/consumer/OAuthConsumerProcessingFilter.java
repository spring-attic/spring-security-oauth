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

package org.springframework.security.oauth.consumer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth.common.OAuthException;
import org.springframework.security.oauth.common.OAuthProviderParameter;
import org.springframework.security.oauth.consumer.token.HttpSessionBasedTokenServicesFactory;
import org.springframework.security.oauth.consumer.token.OAuthConsumerToken;
import org.springframework.security.oauth.consumer.token.OAuthConsumerTokenServices;
import org.springframework.security.oauth.consumer.token.OAuthConsumerTokenServicesFactory;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.util.Assert;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.*;

/**
 * OAuth consumer processing filter. This filter should be applied to requests for OAuth protected resources (see OAuth Core 1.0).<br/><br/>
 * <p/>
 * When servicing a request that requires protected resources, this filter sets a request attribute (default "OAUTH_ACCESS_TOKENS") that contains
 * the list of {@link org.springframework.security.oauth.consumer.token.OAuthConsumerToken}s.
 *
 * @author Ryan Heaton
 * @author Andrew McCall
 */
public class OAuthConsumerProcessingFilter implements Filter, InitializingBean, MessageSourceAware {

  public static final String ACCESS_TOKENS_DEFAULT_ATTRIBUTE = "OAUTH_ACCESS_TOKENS";
  public static final String OAUTH_FAILURE_KEY = "OAUTH_FAILURE_KEY";
  private static final Log LOG = LogFactory.getLog(OAuthConsumerProcessingFilter.class);

  private AuthenticationEntryPoint OAuthFailureEntryPoint;
  protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
  private FilterInvocationSecurityMetadataSource objectDefinitionSource;
  private OAuthConsumerSupport consumerSupport;
  private boolean requireAuthenticated = true;
  private String accessTokensRequestAttribute = ACCESS_TOKENS_DEFAULT_ATTRIBUTE;
  private PortResolver portResolver = new PortResolverImpl();

  private OAuthConsumerTokenServicesFactory tokenServicesFactory = new HttpSessionBasedTokenServicesFactory();
  private ProtectedResourceDetailsService protectedResourceDetailsService;

  public void afterPropertiesSet() throws Exception {
    Assert.notNull(consumerSupport, "Consumer support must be provided.");
    Assert.notNull(tokenServicesFactory, "OAuth token services factory is required.");
    Assert.notNull(protectedResourceDetailsService, "A protected resource details service is required.");
    Assert.notNull(objectDefinitionSource, "The object definition source must be configured.");
  }

  public void init(FilterConfig ignored) throws ServletException {
  }

  public void destroy() {
  }

  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) servletRequest;
    HttpServletResponse response = (HttpServletResponse) servletResponse;

    Set<String> accessTokenDeps = getAccessTokenDependencies(request, response, chain);
    if (!accessTokenDeps.isEmpty()) {
      try {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (requireAuthenticated && !authentication.isAuthenticated()) {
          throw new InsufficientAuthenticationException("An authenticated principal must be present.");
        }

        OAuthConsumerTokenServices tokenServices = getTokenServicesFactory().getTokenServices(authentication, request);
        List<OAuthConsumerToken> tokens = new ArrayList<OAuthConsumerToken>();
        for (String dependency : accessTokenDeps) {
          OAuthConsumerToken token = tokenServices.getToken(dependency);
          if (token == null) {
            if (LOG.isDebugEnabled()) {
              LOG.debug("Obtaining request token for dependency: " + dependency);
            }

            //obtain authorization.
            String callbackURL = response.encodeRedirectURL(getCallbackURL(request));
            OAuthConsumerToken requestToken = getConsumerSupport().getUnauthorizedRequestToken(dependency, callbackURL);

            if (LOG.isDebugEnabled()) {
              LOG.debug("Request token obtained for dependency " + dependency + ": " + requestToken);
            }
            tokenServices.storeToken(dependency, requestToken);
            String redirect = getUserAuthorizationRedirectURL(requestToken, callbackURL);

            if (LOG.isDebugEnabled()) {
              LOG.debug("Redirecting request to " + redirect + " for user authorization of the request token for dependency " + dependency + ".");
            }
            response.sendRedirect(redirect);
            return;
          }
          else {
            if (!token.isAccessToken()) {

              if (LOG.isDebugEnabled()) {
                LOG.debug("Obtaining access token for dependency: " + dependency);
              }

              //authorize the request token and store it.
              try {
                token = getConsumerSupport().getAccessToken(token, request.getParameter(OAuthProviderParameter.oauth_verifier.toString()));
              }
              finally {
                //make sure any request tokens are removed.
                tokenServices.removeToken(dependency);
              }

              if (LOG.isDebugEnabled()) {
                LOG.debug("Access token " + token + " obtained for dependency " + dependency + ". Now storing and using.");
              }

              tokenServices.storeToken(dependency, token);
            }
            else if (LOG.isDebugEnabled()) {
              LOG.debug("Authorized access token " + token + " loaded for dependency " + dependency + ".");
            }

            //token already authorized.
            tokens.add(token);
          }
        }

        if (LOG.isDebugEnabled()) {
          LOG.debug("Storing access tokens in request attribute '" + getAccessTokensRequestAttribute() + "'.");
        }

        request.setAttribute(getAccessTokensRequestAttribute(), tokens);
        chain.doFilter(request, response);
      }
      catch (OAuthException ae) {
        fail(request, response, ae);
      }
      catch (ServletException e) {
        if (e.getRootCause() instanceof OAuthException) {
          fail(request, response, (OAuthException) e.getRootCause());
        }
        else {
          throw e;
        }
      }
    }
    else {
      if (LOG.isDebugEnabled()) {
        LOG.debug("No access token dependencies for request.");
      }
      chain.doFilter(servletRequest, servletResponse);
    }
  }

  /**
   * Get the callback URL for the specified request.
   *
   * @param request The request.
   * @return The callback URL.
   */
  protected String getCallbackURL(HttpServletRequest request) {
    return new DefaultSavedRequest(request, getPortResolver()).getRedirectUrl();
  }

  /**
   * Get the URL to which to redirect the user for authorization of protected resources.
   *
   * @param requestToken The request token.
   * @param callbackURL  The callback URL.
   * @return The URL.
   */
  protected String getUserAuthorizationRedirectURL(OAuthConsumerToken requestToken, String callbackURL) {
    ProtectedResourceDetails details = getProtectedResourceDetailsService().loadProtectedResourceDetailsById(requestToken.getResourceId());
    try {
      String baseURL = details.getUserAuthorizationURL();
      StringBuilder builder = new StringBuilder(baseURL);
      char appendChar = baseURL.indexOf('?') < 0 ? '?' : '&';
      builder.append(appendChar).append("oauth_token=");
      builder.append(URLEncoder.encode(requestToken.getValue(), "UTF-8"));
      if (!details.isUse10a()) {
        builder.append('&').append("oauth_callback=");
        builder.append(URLEncoder.encode(callbackURL, "UTF-8"));
      }
      return builder.toString();
    }
    catch (UnsupportedEncodingException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Common logic for OAuth failed. (Note that the default logic doesn't pass the failure through so as to not mess
   * with the current authentication.)
   *
   * @param request  The request.
   * @param response The response.
   * @param failure  The failure.
   */
  protected void fail(HttpServletRequest request, HttpServletResponse response, OAuthException failure) throws IOException, ServletException {
    try {
      //attempt to set the last exception.
      request.getSession().setAttribute(OAUTH_FAILURE_KEY, failure);
    }
    catch (Exception e) {
      //fall through....
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug(failure);
    }

    if (getOAuthFailureEntryPoint() != null) {
      getOAuthFailureEntryPoint().commence(request, response, failure);
    }
    else {
      throw new RuntimeException("Unexpected OAuth problem.", failure);
    }
  }

  /**
   * Loads the access token dependencies for the given request. This will be a set of {@link ProtectedResourceDetails#getId() resource ids}
   * for which an OAuth access token is required.
   *
   * @param request     The request.
   * @param response    The response
   * @param filterChain The filter chain
   * @return The access token dependencies (could be empty).
   */
  protected Set<String> getAccessTokenDependencies(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {
    Set<String> deps = new TreeSet<String>();

    if (getObjectDefinitionSource() != null) {
      FilterInvocation invocation = new FilterInvocation(request, response, filterChain);
      Collection<ConfigAttribute> attributes = getObjectDefinitionSource().getAttributes(invocation);
      if (attributes != null) {
        for (ConfigAttribute attribute : attributes) {
          deps.add(attribute.getAttribute());
        }
      }
    }
    return deps;
  }

  /**
   * The protected resource details service.
   *
   * @return The protected resource details service.
   */
  public ProtectedResourceDetailsService getProtectedResourceDetailsService() {
    return protectedResourceDetailsService;
  }

  /**
   * The protected resource details service.
   *
   * @param protectedResourceDetailsService
   *         The protected resource details service.
   */
  @Autowired
  public void setProtectedResourceDetailsService(ProtectedResourceDetailsService protectedResourceDetailsService) {
    this.protectedResourceDetailsService = protectedResourceDetailsService;
  }

  /**
   * The authentication entry point.
   *
   * @return The authentication entry point.
   */
  public AuthenticationEntryPoint getOAuthFailureEntryPoint() {
    return OAuthFailureEntryPoint;
  }

  /**
   * The authentication entry point.
   *
   * @param OAuthFailureEntryPoint The authentication entry point.
   */
  public void setOAuthFailureEntryPoint(AuthenticationEntryPoint OAuthFailureEntryPoint) {
    this.OAuthFailureEntryPoint = OAuthFailureEntryPoint;
  }

  /**
   * Get the OAuth token services factory.
   *
   * @return The OAuth token services factory.
   */
  public OAuthConsumerTokenServicesFactory getTokenServicesFactory() {
    return tokenServicesFactory;
  }

  /**
   * The OAuth token services factory.
   *
   * @param tokenServicesFactory The OAuth token services factory.
   */
  @Autowired(required = false)
  public void setTokenServicesFactory(OAuthConsumerTokenServicesFactory tokenServicesFactory) {
    this.tokenServicesFactory = tokenServicesFactory;
  }

  /**
   * The filter invocation definition source.
   *
   * @return The filter invocation definition source.
   */
  public FilterInvocationSecurityMetadataSource getObjectDefinitionSource() {
    return objectDefinitionSource;
  }

  /**
   * The filter invocation definition source.
   *
   * @param objectDefinitionSource The filter invocation definition source.
   */
  public void setObjectDefinitionSource(FilterInvocationSecurityMetadataSource objectDefinitionSource) {
    this.objectDefinitionSource = objectDefinitionSource;
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
   * The OAuth consumer support.
   *
   * @return The OAuth consumer support.
   */
  public OAuthConsumerSupport getConsumerSupport() {
    return consumerSupport;
  }

  /**
   * The OAuth consumer support.
   *
   * @param consumerSupport The OAuth consumer support.
   */
  @Autowired
  public void setConsumerSupport(OAuthConsumerSupport consumerSupport) {
    this.consumerSupport = consumerSupport;
  }

  /**
   * Whether to require the current authentication to be authenticated.
   *
   * @return Whether to require the current authentication to be authenticated.
   */
  public boolean isRequireAuthenticated() {
    return requireAuthenticated;
  }

  /**
   * Whether to require the current authentication to be authenticated.
   *
   * @param requireAuthenticated Whether to require the current authentication to be authenticated.
   */
  public void setRequireAuthenticated(boolean requireAuthenticated) {
    this.requireAuthenticated = requireAuthenticated;
  }

  /**
   * The default request attribute into which the OAuth access tokens are stored.
   *
   * @return The default request attribute into which the OAuth access tokens are stored.
   */
  public String getAccessTokensRequestAttribute() {
    return accessTokensRequestAttribute;
  }

  /**
   * The default request attribute into which the OAuth access tokens are stored.
   *
   * @param accessTokensRequestAttribute The default request attribute into which the OAuth access tokens are stored.
   */
  public void setAccessTokensRequestAttribute(String accessTokensRequestAttribute) {
    this.accessTokensRequestAttribute = accessTokensRequestAttribute;
  }

  /**
   * The port resolver.
   *
   * @return The port resolver.
   */
  public PortResolver getPortResolver() {
    return portResolver;
  }

  /**
   * The port resolver.
   *
   * @param portResolver The port resolver.
   */
  @Autowired(required = false)
  public void setPortResolver(PortResolver portResolver) {
    this.portResolver = portResolver;
  }

}