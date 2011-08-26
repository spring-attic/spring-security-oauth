/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.provider.web;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.servlet.HandlerAdapter;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.annotation.AnnotationMethodHandlerAdapter;
import org.springframework.web.servlet.mvc.annotation.DefaultAnnotationHandlerMapping;

/**
 * @author Dave Syer
 * 
 */
public class FrameworkEndpointHandlerMapping extends DefaultAnnotationHandlerMapping implements HandlerAdapter {

	private AnnotationMethodHandlerAdapter delegate = new AnnotationMethodHandlerAdapter();
	private Map<String, String> overrides = new HashMap<String, String>();

	public FrameworkEndpointHandlerMapping() {
		setOrder(0);
	}

	public void setPathOverrides(Map<String, String> overrides) {
		this.overrides = overrides;
		delegate.setPathMatcher(new OverridingPathMatcher(overrides));
	}

	public boolean supports(Object handler) {
		if (!(handler instanceof FrameworkEndpointWrapper)) {
			return false;
		}
		return delegate.supports(((FrameworkEndpointWrapper) handler).getDelegate());
	}

	public ModelAndView handle(HttpServletRequest request, HttpServletResponse response, Object handler)
			throws Exception {
		return delegate.handle(request, response, ((FrameworkEndpointWrapper) handler).getDelegate());
	}

	public long getLastModified(HttpServletRequest request, Object handler) {
		return delegate.getLastModified(request, ((FrameworkEndpointWrapper) handler).getDelegate());
	}

	@Override
	protected String[] determineUrlsForHandler(String beanName) {
		ApplicationContext context = getApplicationContext();
		Class<?> handlerType = context.getType(beanName);
		if (AnnotationUtils.findAnnotation(handlerType, FrameworkEndpoint.class) != null) {
			String[] results = determineUrlsForHandlerMethods(handlerType, false);
			if (results != null) {
				String[] replacements = new String[results.length];
				for (int i = 0; i < replacements.length; i++) {
					String match = results[i];
					if (overrides.containsKey(match)) {
						replacements[i] = overrides.get(match);
					} else {
						replacements[i] = match;
					}
				}
				results = replacements;
			}
			return results;
		}
		return null;
	}

	@Override
	protected void registerHandler(String urlPath, Object handler) throws BeansException, IllegalStateException {
		super.registerHandler(urlPath, new FrameworkEndpointWrapper(handler, getApplicationContext()));
	}

	private static class OverridingPathMatcher extends AntPathMatcher {

		private final Map<String, String> overrides;

		public OverridingPathMatcher(Map<String, String> overrides) {
			this.overrides = overrides;
		}

		@Override
		protected boolean doMatch(String pattern, String path, boolean fullMatch,
				Map<String, String> uriTemplateVariables) {
			if (overrides.containsKey(pattern)) {
				pattern = overrides.get(pattern);
			}
			return super.doMatch(pattern, path, fullMatch, uriTemplateVariables);
		}
	}
}
