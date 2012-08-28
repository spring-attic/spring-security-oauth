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
import java.util.Map;
import java.util.Set;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.web.servlet.mvc.condition.PatternsRequestCondition;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

/**
 * A handler mapping for framework endpoints (those annotated with &#64;FrameworkEndpoint).
 * 
 * @author Dave Syer
 * 
 */
public class FrameworkEndpointHandlerMapping extends RequestMappingHandlerMapping {

	private Map<String, String> mappings = new HashMap<String, String>();

	/**
	 * Custom mappings for framework endpoint paths. The keys in the map are the default framework endpoint path,
	 * e.g. "/oauth/authorize", and the values are the desired runtime paths.
	 * 
	 * @param mappings the mappings to set
	 */
	public void setMappings(Map<String, String> patternMap) {
		this.mappings = patternMap;
	}

	public FrameworkEndpointHandlerMapping() {
		// Make sure user-supplied mappings take precedence by default (except the resource mapping)
		setOrder(Ordered.LOWEST_PRECEDENCE - 1);
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
			patterns[i] = pattern;
			if (mappings.containsKey(pattern)) {
				patterns[i] = mappings.get(pattern);
			}
			i++;
		}
		PatternsRequestCondition patternsInfo = new PatternsRequestCondition(patterns);

		RequestMappingInfo mapping = new RequestMappingInfo(patternsInfo, defaultMapping.getMethodsCondition(),
				defaultMapping.getParamsCondition(), defaultMapping.getHeadersCondition(),
				defaultMapping.getConsumesCondition(), defaultMapping.getProducesCondition(),
				defaultMapping.getCustomCondition());
		return mapping;

	}

}
