/*
 * Copyright 2006-2011 the original author or authors.
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

package org.springframework.security.oauth2.provider.endpoint;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.mvc.condition.NameValueExpression;
import org.springframework.web.servlet.mvc.condition.ParamsRequestCondition;
import org.springframework.web.servlet.mvc.condition.PatternsRequestCondition;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.servlet.view.UrlBasedViewResolver;

/**
 * A handler mapping for framework endpoints (those annotated with &#64;FrameworkEndpoint).
 * 
 * @author Dave Syer
 * 
 */
public class FrameworkEndpointHandlerMapping extends RequestMappingHandlerMapping {

	private static final String REDIRECT = UrlBasedViewResolver.REDIRECT_URL_PREFIX;

	private static final String FORWARD = UrlBasedViewResolver.FORWARD_URL_PREFIX;

	private Map<String, String> mappings = new HashMap<String, String>();

	private String approvalParameter = OAuth2Utils.USER_OAUTH_APPROVAL;

	private Set<String> paths = new HashSet<String>();

	private String prefix;

	/**
	 * @param prefix the prefix to set
	 */
	public void setPrefix(String prefix) {
		if (!StringUtils.hasText(prefix)) {
			prefix = "";
		}
		else
			while (prefix.endsWith("/")) {
				prefix = prefix.substring(0, prefix.lastIndexOf("/"));
			}
		this.prefix = prefix;
	}

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
	public String getServletPath(String defaultPath) {
		return (prefix == null ? "" : prefix) + getPath(defaultPath);
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

	public Set<String> getPaths() {
		return paths;
	}

	/**
	 * The name of the request parameter that distinguishes a call to approve an authorization. Default is
	 * {@link OAuth2Utils#USER_OAUTH_APPROVAL}.
	 * 
	 * @param approvalParameter the approvalParameter to set
	 */
	public void setApprovalParameter(String approvalParameter) {
		this.approvalParameter = approvalParameter;
	}

	public FrameworkEndpointHandlerMapping() {
		// Make sure user-supplied mappings take precedence by default (except the resource mapping)
		setOrder(Ordered.LOWEST_PRECEDENCE - 2);
	}

	/**
	 * Detects &#64;FrameworkEndpoint annotations in handler beans.
	 * 
	 * @see org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping#isHandler(java.lang.Class)
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
		PatternsRequestCondition patternsInfo = new PatternsRequestCondition(patterns, getUrlPathHelper(),
				getPathMatcher(), useSuffixPatternMatch(), useTrailingSlashMatch(), getFileExtensions());

		ParamsRequestCondition paramsInfo = defaultMapping.getParamsCondition();
		if (!approvalParameter.equals(OAuth2Utils.USER_OAUTH_APPROVAL) && defaultPatterns.contains("/oauth/authorize")) {
			String[] params = new String[paramsInfo.getExpressions().size()];
			Set<NameValueExpression<String>> expressions = paramsInfo.getExpressions();
			i = 0;
			for (NameValueExpression<String> expression : expressions) {
				String param = expression.toString();
				if (OAuth2Utils.USER_OAUTH_APPROVAL.equals(param)) {
					params[i] = approvalParameter;
				}
				else {
					params[i] = param;
				}
				i++;
			}
			paramsInfo = new ParamsRequestCondition(params);
		}

		RequestMappingInfo mapping = new RequestMappingInfo(patternsInfo, defaultMapping.getMethodsCondition(),
				paramsInfo, defaultMapping.getHeadersCondition(), defaultMapping.getConsumesCondition(),
				defaultMapping.getProducesCondition(), defaultMapping.getCustomCondition());
		return mapping;

	}

}
