/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */

package org.springframework.security.oauth2.provider.expression;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.core.MethodParameter;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.expression.AccessException;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.MethodExecutor;
import org.springframework.expression.MethodResolver;
import org.springframework.expression.TypedValue;
import org.springframework.expression.spel.support.ReflectionHelper;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.core.Authentication;
import org.springframework.util.ReflectionUtils;
import org.springframework.util.ReflectionUtils.MethodCallback;
import org.springframework.util.ReflectionUtils.MethodFilter;

/**
 * A method resolver that can bypass the normal security root and divert methd executions to a special OAuth2 expression
 * root.
 * 
 * @author Dave Syer
 * 
 */
public class OAuth2MethodResolver implements MethodResolver {

	private static Map<String, OAuthMethodExecutor> methods = new HashMap<String, OAuthMethodExecutor>();

	private ThreadLocal<OAuth2SecurityExpressionRoot> root = new ThreadLocal<OAuth2SecurityExpressionRoot>();

	/**
	 * Store the current authentication in a thread local so it can be used for security expression evaluation.
	 * Unfortunately it has to be thread local because method resolver results are cached internally in SpEL nodes
	 * (independent of evaluation context).
	 * 
	 * @param authentication the current authentication
	 */
	public void setAuthentication(Authentication authentication) {
		this.root.set(new OAuth2SecurityExpressionRoot(authentication));
	}

	/**
	 * Provide an opportunity for callers to clear the thread local context.
	 */
	public void clearAuthentication() {
		this.root.set(null);
	}

	/**
	 * Resolve to a special method executor if it looks like it can be evaluated on an
	 * {@link OAuth2SecurityExpressionRoot}.
	 * 
	 * @see org.springframework.expression.MethodResolver#resolve(org.springframework.expression.EvaluationContext,
	 * java.lang.Object, java.lang.String, java.util.List)
	 */
	public MethodExecutor resolve(EvaluationContext context, Object targetObject, String name,
			List<TypeDescriptor> argumentTypes) throws AccessException {
		if (targetObject instanceof SecurityExpressionRoot) {
			if (name.equals("oauthSufficientScope")) {
				getRoot().setThrowExceptionOnInvalidScope(false);
			}
			if (name.startsWith("oauth") || name.equals("denyOAuthClient")) {
				OAuthMethodExecutor executor = getMethodByName(name);
				return executor;
			}
		}

		return null;
	}

	private OAuth2SecurityExpressionRoot getRoot() {
		return root.get();
	}

	private OAuthMethodExecutor getMethodByName(final String name) {
		if (!methods.containsKey(name)) {
			ReflectionUtils.doWithMethods(OAuth2SecurityExpressionRoot.class, new MethodCallback() {
				public void doWith(Method method) throws IllegalArgumentException, IllegalAccessException {
					methods.put(name, new OAuthMethodExecutor(method));
				}
			}, new MethodFilter() {
				public boolean matches(Method method) {
					return method.getName().equals(name);
				}
			});
		}
		return methods.get(name);
	}

	private class OAuthMethodExecutor implements MethodExecutor {

		private final Method method;

		public OAuthMethodExecutor(Method method) {
			this.method = method;
		}

		public TypedValue execute(EvaluationContext context, Object target, Object... arguments) throws AccessException {
			try {
				if (arguments != null) {
					ReflectionHelper.convertAllArguments(context.getTypeConverter(), arguments, method);
				}
				if (this.method.isVarArgs()) {
					arguments = ReflectionHelper.setupArgumentsForVarargsInvocation(this.method.getParameterTypes(),
							arguments);
				}
				ReflectionUtils.makeAccessible(this.method);
				Object value = this.method.invoke(getRoot(), arguments);
				return new TypedValue(value, new TypeDescriptor(new MethodParameter(this.method, -1)).narrow(value));
			}
			catch (Exception ex) {
				throw new AccessException("Problem invoking method: " + this.method, ex);
			}
		}

	}

}