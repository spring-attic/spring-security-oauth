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

import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;

/**
 * A security expression handler that can handle default web security expressions plus the set provided by
 * {@link OAuth2SecurityExpressionMethods} using the variable oauth2 to access the methods. For example, the expression
 * <code>#oauth2.clientHasRole('ROLE_ADMIN')</code> would invoke {@link OAuth2SecurityExpressionMethods#clientHasRole}.
 * 
 * @author Dave Syer
 * @author Rob Winch
 * 
 */
public class OAuth2WebSecurityExpressionHandler extends DefaultWebSecurityExpressionHandler {
	private boolean throwExceptionOnInvalidScope = true;

	/**
	 * Flag to determine the behaviour on access denied if the reason is . If set then we throw an
	 * {@link InvalidScopeException} instead of returning true. This is unconventional for an access decision because it
	 * vetos the other voters in the chain, but it enables us to pass a message to the caller with information about the
	 * required scope.
	 * 
	 * @param throwException the flag to set (default true)
	 */
	public void setThrowExceptionOnInvalidScope(boolean throwException) {
		this.throwExceptionOnInvalidScope = throwException;
	}
	
	@Override
	protected StandardEvaluationContext createEvaluationContextInternal(Authentication authentication,
			FilterInvocation invocation) {
		StandardEvaluationContext ec = super.createEvaluationContextInternal(authentication, invocation);
		ec.setVariable("oauth2", new OAuth2SecurityExpressionMethods(authentication, throwExceptionOnInvalidScope));
		return ec;
	}
}