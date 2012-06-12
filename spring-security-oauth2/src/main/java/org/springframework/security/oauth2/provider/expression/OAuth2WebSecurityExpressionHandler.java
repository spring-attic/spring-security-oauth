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
package org.springframework.security.oauth2.provider.expression;

import org.springframework.beans.factory.DisposableBean;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;

/**
 * A security expression handler that can handle default web security expressions plus the set provided by
 * {@link OAuth2SecurityExpressionRoot} (which see).
 * 
 * @author Dave Syer
 * 
 */
public class OAuth2WebSecurityExpressionHandler extends DefaultWebSecurityExpressionHandler implements DisposableBean {

	private OAuth2MethodResolver resolver = new OAuth2MethodResolver();

	@Override
	protected StandardEvaluationContext createEvaluationContextInternal(Authentication authentication,
			FilterInvocation invocation) {
		StandardEvaluationContext ec = super.createEvaluationContextInternal(authentication, invocation);
		ec.addMethodResolver(resolver);
		resolver.setAuthentication(authentication);
		return ec;
	}

	public void destroy() throws Exception {
		resolver.clearAuthentication();
	}

}