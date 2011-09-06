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

package org.springframework.security.oauth2.client.filter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.client.OAuth2AccessTokenRequiredException;
import org.springframework.security.oauth2.client.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.OAuth2ProtectedResourceDetailsService;
import org.springframework.security.oauth2.client.OAuth2SecurityContext;
import org.springframework.security.oauth2.client.OAuth2SecurityContextHolder;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.util.Assert;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

/**
 * OAuth 2 client processing filter. Used to lock down requests (based on standard spring security URL pattern matching) according to the availability of
 * certain OAuth 2 access tokens.<br/><br/>
 * <p/>
 * When servicing a request that requires protected resources, this filter sets a request attribute (default "OAUTH_ACCESS_TOKENS") that contains
 * the list of {@link org.springframework.security.oauth2.common.OAuth2AccessToken}s.
 *
 * @author Ryan Heaton
 */
public class OAuth2ClientProcessingFilter implements Filter, InitializingBean, MessageSourceAware {

  public static final String ACCESS_TOKENS_DEFAULT_ATTRIBUTE = "OAUTH_ACCESS_TOKENS";
  private static final Log LOG = LogFactory.getLog(OAuth2ClientProcessingFilter.class);

  protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
  private FilterInvocationSecurityMetadataSource objectDefinitionSource;
  private String accessTokensRequestAttribute = ACCESS_TOKENS_DEFAULT_ATTRIBUTE;
  private OAuth2ProtectedResourceDetailsService resourceDetailsService;

  public void afterPropertiesSet() throws Exception {
    Assert.notNull(objectDefinitionSource, "The object definition source must be configured.");
    Assert.notNull(resourceDetailsService, "A resource details service must be configured for the client processing filter.");
  }

  public void init(FilterConfig ignored) throws ServletException {
  }

  public void destroy() {
  }

  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) servletRequest;
    HttpServletResponse response = (HttpServletResponse) servletResponse;

    Set<String> resourceDependencies = getResourceDependencies(request, response, chain);
    if (!resourceDependencies.isEmpty()) {
      OAuth2SecurityContext context = OAuth2SecurityContextHolder.getContext();
      if (context == null) {
        throw new IllegalStateException("An OAuth2 security context hasn't been established. Unable to load the access tokens for the following resources: " + resourceDependencies);
      }

      Map<String, OAuth2AccessToken> accessTokens = context.getAccessTokens();
      List<OAuth2AccessToken> tokens = new ArrayList<OAuth2AccessToken>();
      for (String dependency : resourceDependencies) {
        OAuth2ProtectedResourceDetails resource = getResourceDetailsService().loadProtectedResourceDetailsById(dependency);
        if (resource == null) {
          throw new IllegalStateException("Unknown resource: " + dependency);
        }

        OAuth2AccessToken accessToken = accessTokens == null ? null : accessTokens.get(dependency);
        if (accessToken == null) {
          throw new OAuth2AccessTokenRequiredException("Access token for resource '" + dependency + "' has not been obtained.", resource);
        }
        else {
          tokens.add(accessToken);
        }
      }

      if (LOG.isDebugEnabled()) {
        LOG.debug("Storing access tokens in request attribute '" + getAccessTokensRequestAttribute() + "'.");
      }

      request.setAttribute(getAccessTokensRequestAttribute(), tokens);
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
   * Loads the resource dependencies for the given request. This will be a set of {@link org.springframework.security.oauth2.client.OAuth2ProtectedResourceDetails#getId() resource ids}
   * for which an OAuth2 access token is required.
   *
   * @param request     The request.
   * @param response    The response
   * @param filterChain The filter chain
   * @return The resource dependencies (could be empty).
   */
  protected Set<String> getResourceDependencies(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {
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
   * The resource details service.
   *
   * @return The resource details service.
   */
  public OAuth2ProtectedResourceDetailsService getResourceDetailsService() {
    return resourceDetailsService;
  }

  /**
   * The resource details service.
   *
   * @param resourceDetailsService The resource details service.
   */
  public void setResourceDetailsService(OAuth2ProtectedResourceDetailsService resourceDetailsService) {
    this.resourceDetailsService = resourceDetailsService;
  }
}