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

import java.io.IOException;
import java.util.Collection;
import java.util.Set;
import java.util.TreeSet;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.oauth2.client.context.OAuth2ClientContext;
import org.springframework.security.oauth2.client.context.OAuth2ClientContextHolder;
import org.springframework.security.oauth2.client.http.AccessTokenRequiredException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetailsService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.util.Assert;

/**
 * <p>
 * OAuth 2 client processing filter. Used to lock down requests (based on standard spring security URL pattern matching)
 * according to the availability of certain OAuth 2 access tokens.<br/>
 * <p/>
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class OAuth2ClientProcessingFilter implements Filter, InitializingBean {

	private static final Log logger = LogFactory.getLog(OAuth2ClientProcessingFilter.class);

	private FilterInvocationSecurityMetadataSource objectDefinitionSource;

	private OAuth2ProtectedResourceDetailsService resourceDetailsService;

	public void afterPropertiesSet() throws Exception {
		Assert.notNull(objectDefinitionSource, "The object definition source must be configured.");
		Assert.notNull(resourceDetailsService,
				"A resource details service must be configured for the client processing filter.");
	}

	public void init(FilterConfig ignored) throws ServletException {
	}

	public void destroy() {
	}

	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
			throws IOException, ServletException {

		HttpServletRequest request = (HttpServletRequest) servletRequest;
		HttpServletResponse response = (HttpServletResponse) servletResponse;

		Set<String> resourceDependencies = getResourceDependencies(request, response, chain);

		if (!resourceDependencies.isEmpty()) {

			OAuth2ClientContext context = OAuth2ClientContextHolder.getContext();
			if (context == null) {
				throw new IllegalStateException(
						"An OAuth2 security context hasn't been established. Unable to load the access tokens for the following resources: "
								+ resourceDependencies);
			}

			for (String dependency : resourceDependencies) {
				OAuth2ProtectedResourceDetails resource = resourceDetailsService
						.loadProtectedResourceDetailsById(dependency);
				if (resource == null) {
					throw new IllegalStateException("Unknown resource: " + dependency);
				}

				OAuth2AccessToken accessToken = context.getAccessToken(resource);
				if (accessToken == null) {
					throw new AccessTokenRequiredException("Access token for resource '" + dependency
							+ "' has not been obtained.", resource);
				}
			}

			chain.doFilter(request, response);

		}
		else {
			if (logger.isDebugEnabled()) {
				logger.debug("No access token dependencies for request.");
			}
			chain.doFilter(servletRequest, servletResponse);
		}

	}

	/**
	 * Loads the resource dependencies for the given request. This will be a set of
	 * {@link org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails#getId() resource ids}
	 * for which an OAuth2 access token is required.
	 * 
	 * @param request The request.
	 * @param response The response
	 * @param filterChain The filter chain
	 * @return The resource dependencies (could be empty).
	 */
	protected Set<String> getResourceDependencies(HttpServletRequest request, HttpServletResponse response,
			FilterChain filterChain) {

		Set<String> deps = new TreeSet<String>();

		if (objectDefinitionSource != null) {
			FilterInvocation invocation = new FilterInvocation(request, response, filterChain);
			Collection<ConfigAttribute> attributes = objectDefinitionSource.getAttributes(invocation);
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
	 * @param objectDefinitionSource The filter invocation definition source.
	 */
	public void setObjectDefinitionSource(FilterInvocationSecurityMetadataSource objectDefinitionSource) {
		this.objectDefinitionSource = objectDefinitionSource;
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