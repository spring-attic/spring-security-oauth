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

import org.springframework.security.access.expression.AbstractSecurityExpressionHandler;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.web.FilterInvocation;

/**
 * @author Dave Syer
 * 
 */
public class OAuth2WebSecurityExpressionHandler extends AbstractSecurityExpressionHandler<FilterInvocation> {

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
	protected SecurityExpressionRoot createSecurityExpressionRoot(Authentication authentication, FilterInvocation fi) {
		OAuth2WebSecurityExpressionRoot root = new OAuth2WebSecurityExpressionRoot(authentication, fi, throwExceptionOnInvalidScope);
		root.setPermissionEvaluator(getPermissionEvaluator());
		return root;
	}
}