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

package org.springframework.security.oauth.consumer.filter;

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
import org.springframework.security.oauth.consumer.AccessTokenRequiredException;
import org.springframework.security.oauth.consumer.OAuthConsumerToken;
import org.springframework.security.oauth.consumer.OAuthSecurityContext;
import org.springframework.security.oauth.consumer.OAuthSecurityContextHolder;
import org.springframework.security.oauth.consumer.ProtectedResourceDetails;
import org.springframework.security.oauth.consumer.ProtectedResourceDetailsService;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.util.Assert;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * OAuth consumer processing filter. This filter should be applied to requests for OAuth protected resources (see OAuth Core 1.0).
 * 
 * When servicing a request that requires protected resources, this filter sets a request attribute (default "OAUTH_ACCESS_TOKENS") that contains
 * the list of {@link org.springframework.security.oauth.consumer.OAuthConsumerToken}s.
 *
 * @author Ryan Heaton
 * @author Andrew McCall
 */
public class OAuthConsumerProcessingFilter implements Filter, InitializingBean, MessageSourceAware {

  private static final Log LOG = LogFactory.getLog(OAuthConsumerProcessingFilter.class);

  protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
  private FilterInvocationSecurityMetadataSource objectDefinitionSource;
  private boolean requireAuthenticated = true;

  private ProtectedResourceDetailsService protectedResourceDetailsService;

  public void afterPropertiesSet() throws Exception {
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
      Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
      if (isRequireAuthenticated() && !authentication.isAuthenticated()) {
        throw new InsufficientAuthenticationException("An authenticated principal must be present.");
      }

      OAuthSecurityContext context = OAuthSecurityContextHolder.getContext();
      if (context == null) {
        throw new IllegalStateException("No OAuth security context has been established. Unable to access resources.");
      }

      Map<String, OAuthConsumerToken> accessTokens = context.getAccessTokens();

      for (String dependency : accessTokenDeps) {
        if (!accessTokens.containsKey(dependency)) {
          throw new AccessTokenRequiredException(getProtectedResourceDetailsService().loadProtectedResourceDetailsById(dependency));
        }
      }

      chain.doFilter(request, response);
    }
    else {
      if (LOG.isDebugEnabled()) {
        LOG.debug("No access token dependencies for request.");
      }
      chain.doFilter(servletRequest, servletResponse);
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

}
