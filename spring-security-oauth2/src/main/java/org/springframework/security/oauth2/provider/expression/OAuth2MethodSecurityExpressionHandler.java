package org.springframework.security.oauth2.provider.expression;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.core.Authentication;

/**
 * A security expression handler that can handle default method security expressions plus the set provided by
 * {@link OAuth2SecurityExpressionMethods} using the variable oauth2 to access the methods. For example, the expression
 * <code>#oauth2.clientHasRole('ROLE_ADMIN')</code> would invoke {@link OAuth2SecurityExpressionMethods#clientHasRole}
 *
 * @author Dave Syer
 * @author Rob Winch
 */
public class OAuth2MethodSecurityExpressionHandler extends DefaultMethodSecurityExpressionHandler {
	
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
	public StandardEvaluationContext createEvaluationContextInternal(Authentication authentication, MethodInvocation mi) {
		StandardEvaluationContext ec = super.createEvaluationContextInternal(authentication, mi);
		ec.setVariable("oauth2", new OAuth2SecurityExpressionMethods(authentication, throwExceptionOnInvalidScope));
		return ec;
	}
}
