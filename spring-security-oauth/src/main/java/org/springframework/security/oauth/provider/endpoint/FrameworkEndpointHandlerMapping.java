/*
 * Copyright 2006-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.oauth.provider.endpoint;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.web.servlet.mvc.condition.ParamsRequestCondition;
import org.springframework.web.servlet.mvc.condition.PatternsRequestCondition;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.servlet.view.UrlBasedViewResolver;

import java.lang.reflect.Method;
import java.util.*;

/**
 * A handler mapping for framework endpoints (those annotated with &#64;FrameworkEndpoint).
 *
 * @author Dave Syer
 * @author <a rel="author" href="http://autayeu.com/">Aliaksandr Autayeu</a>
 */
public class FrameworkEndpointHandlerMapping extends RequestMappingHandlerMapping {

	private static final String REDIRECT = UrlBasedViewResolver.REDIRECT_URL_PREFIX;

	private static final String FORWARD = UrlBasedViewResolver.FORWARD_URL_PREFIX;

	// default framework endpoint path -> custom path
	private Map<String, String> mappings = new HashMap<String, String>();

	// set of all default framework endpoint paths (usually 3: request token, access token and authorize token)
	private final Set<String> paths = new HashSet<String>();
	// set of all default framework endpoint paths which require OAuth-authenticated request
	// usually 2: request token and access token
	private final Set<String> oauthAuthenticatedPaths = new HashSet<String>();

	/**
	 * Custom mappings for framework endpoint paths. The keys in the map are the default framework endpoint path, e.g.
	 * "/oauth/authorize", and the values are the desired runtime paths.
	 *
	 * @param patternMap the mappings to set
	 */
	public void setMappings(Map<String, String> patternMap) {
		this.mappings = new HashMap<String, String>(patternMap);
		for (String key : mappings.keySet()) {
			String result = mappings.get(key);
			if (result.startsWith(FORWARD)) {
				result = result.substring(FORWARD.length());
			}
			if (result.startsWith(REDIRECT)) {
				result = result.substring(REDIRECT.length());
			}
			mappings.put(key, result);
		}
	}

	/**
	 * @return the mapping from default endpoint paths to custom ones (or the default if no customization is known)
	 */
	public String getPath(String defaultPath) {
		String result = defaultPath;
		if (mappings.containsKey(defaultPath)) {
			result = mappings.get(defaultPath);
		}
		return result;
	}

	/**
	 * Set of all default framework endpoint paths.
	 * Usually has 3 entries: request token, access token and authorize token.
	 *
	 * @return set of all default framework endpoint paths
	 */
	public Set<String> getPaths() {
		return Collections.unmodifiableSet(paths);
	}

	/**
	 * Set of all default framework endpoint paths which require OAuth-authenticated request.
	 * Usually has 2 entries: request token, access token.
	 *
	 * @return set of all default framework endpoint paths which require OAuth-authenticated request.
	 */
	public Set<String> getOAuthAuthenticatedPaths() {
		return Collections.unmodifiableSet(oauthAuthenticatedPaths);
	}

	public FrameworkEndpointHandlerMapping() {
		// Make sure user-supplied mappings take precedence by default (except the resource mapping)
		setOrder(Ordered.LOWEST_PRECEDENCE - 1);
	}

	/**
	 * Detects &#64;FrameworkEndpoint annotations in handler beans.
	 *
	 * @see org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping#isHandler(Class)
	 */
	@Override
	protected boolean isHandler(Class<?> beanType) {
		return AnnotationUtils.findAnnotation(beanType, FrameworkEndpoint.class) != null;
	}

	@Override
	protected RequestMappingInfo getMappingForMethod(Method method, Class<?> handlerType) {
		RequestMappingInfo defaultMapping = super.getMappingForMethod(method, handlerType);
		if (defaultMapping == null) {
			return null;
		}

		Set<String> defaultPatterns = defaultMapping.getPatternsCondition().getPatterns();
		String[] patterns = new String[defaultPatterns.size()];

		int i = 0;
		for (String pattern : defaultPatterns) {
			patterns[i] = getPath(pattern);
			paths.add(pattern);
			i++;
		}

		// check if this endpoint requires OAuth-authentication
		FrameworkEndpoint frameworkEndpoint = AnnotationUtils.findAnnotation(handlerType, FrameworkEndpoint.class);
		if (null != frameworkEndpoint && frameworkEndpoint.oauthAuthenticationRequired()) {
			oauthAuthenticatedPaths.addAll(defaultPatterns);
		}

		PatternsRequestCondition patternsInfo = new PatternsRequestCondition(patterns);

		ParamsRequestCondition paramsInfo = defaultMapping.getParamsCondition();

		return new RequestMappingInfo(patternsInfo, defaultMapping.getMethodsCondition(),
									  paramsInfo, defaultMapping.getHeadersCondition(), defaultMapping.getConsumesCondition(),
									  defaultMapping.getProducesCondition(), defaultMapping.getCustomCondition());
	}
}