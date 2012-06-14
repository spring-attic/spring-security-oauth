package org.springframework.security.oauth2.provider.expression;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.core.Authentication;

/**
 * <p>
 * A security expression handler that can handle default method security expressions plus the set provided by
 * {@link OAuth2SecurityExpressionMethods} using the variable oauth2 to access the methods. For example, the expression
 * <code>#oauth2.clientHasRole('ROLE_ADMIN')</code> would invoke {@link OAuth2SecurityExpressionMethods#clientHasRole}
 * </p>
 * <p>
 * By default the {@link OAuth2ExpressionParser} is used. If this is undesirable one can inject their own
 * {@link ExpressionParser} using {@link #setExpressionParser(ExpressionParser)}.
 * </p>
 * 
 * @author Dave Syer
 * @author Rob Winch
 * @see OAuth2ExpressionParser
 */
public class OAuth2MethodSecurityExpressionHandler extends DefaultMethodSecurityExpressionHandler {

	public OAuth2MethodSecurityExpressionHandler() {
		setExpressionParser(new OAuth2ExpressionParser(getExpressionParser()));
	}

	@Override
	public StandardEvaluationContext createEvaluationContextInternal(Authentication authentication, MethodInvocation mi) {
		StandardEvaluationContext ec = super.createEvaluationContextInternal(authentication, mi);
		ec.setVariable("oauth2", new OAuth2SecurityExpressionMethods(authentication));
		return ec;
	}
}
