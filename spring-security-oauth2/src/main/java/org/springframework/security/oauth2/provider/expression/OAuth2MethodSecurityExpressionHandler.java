package org.springframework.security.oauth2.provider.expression;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.core.Authentication;

/**
 * A security expression handler that can handle default web security expressions plus the set provided by
 * {@link OAuth2SecurityExpressionRoot} (which see).
 *
 * @author Dave Syer
 */
public class OAuth2MethodSecurityExpressionHandler extends DefaultMethodSecurityExpressionHandler implements DisposableBean {

	private OAuth2MethodResolver resolver = new OAuth2MethodResolver();

	@Override
	public StandardEvaluationContext createEvaluationContextInternal(Authentication authentication, MethodInvocation mi) {
		StandardEvaluationContext ec = super.createEvaluationContextInternal(authentication, mi);
		ec.addMethodResolver(resolver);
		resolver.setAuthentication(authentication);
		return ec;
	}

	public void destroy() throws Exception {
		resolver.clearAuthentication();
	}

}
