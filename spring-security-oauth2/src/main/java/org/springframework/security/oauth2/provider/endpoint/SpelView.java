/*
 * Copyright 2013-2014 the original author or authors.
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

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.expression.MapAccessor;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.util.PropertyPlaceholderHelper;
import org.springframework.util.PropertyPlaceholderHelper.PlaceholderResolver;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

/**
 * Simple String template renderer.
 * 
 */
class SpelView implements View {

	private final String template;

	private final SpelExpressionParser parser = new SpelExpressionParser();

	private final StandardEvaluationContext context = new StandardEvaluationContext();

	private PropertyPlaceholderHelper helper;

	private PlaceholderResolver resolver;

	public SpelView(String template) {
		this.template = template;
		this.context.addPropertyAccessor(new MapAccessor());
		this.helper = new PropertyPlaceholderHelper("${", "}");
		this.resolver = new PlaceholderResolver() {
			public String resolvePlaceholder(String name) {
				Expression expression = parser.parseExpression(name);
				Object value = expression.getValue(context);
				return value == null ? null : value.toString();
			}
		};
	}

	public String getContentType() {
		return "text/html";
	}

	public void render(Map<String, ?> model, HttpServletRequest request, HttpServletResponse response)
			throws Exception {
		Map<String, Object> map = new HashMap<String, Object>(model);
		String path = ServletUriComponentsBuilder.fromContextPath(request).build()
				.getPath();
		map.put("path", (Object) path==null ? "" : path);
		context.setRootObject(map);
		String result = helper.replacePlaceholders(template, resolver);
		response.setContentType(getContentType());
		response.getWriter().append(result);
	}

}