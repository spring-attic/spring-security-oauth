package org.springframework.security.oauth2.provider.expression;

import java.util.List;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.expression.AccessException;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.MethodExecutor;
import org.springframework.expression.MethodResolver;
import org.springframework.expression.TypedValue;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.core.Authentication;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class OAuth2MethodSecurityExpressionHandler extends DefaultMethodSecurityExpressionHandler {

	@Override
	public StandardEvaluationContext createEvaluationContextInternal(Authentication auth, MethodInvocation mi) {
		StandardEvaluationContext ec = super.createEvaluationContextInternal(auth, mi);
		ec.addMethodResolver(new OAuthMethodResolver());
		return ec;
	}

	private static class OAuthMethodResolver implements MethodResolver {
		public MethodExecutor resolve(EvaluationContext context, Object targetObject, String name,
				List<TypeDescriptor> argumentTypes) throws AccessException {
			if (targetObject instanceof SecurityExpressionRoot) {
				if ("oauthClientHasRole".equals(name) || "oauthClientHasAnyRole".equals(name)) {
					return new OAuthClientRoleExecutor();
				}
				else if ("oauthHasScope".equals(name) || "oauthHasAnyScope".equals(name)) {
					return new OAuthScopeExecutor();
				}
				else if ("denyOAuthClient".equals(name)) {
					return new DenyOAuthClientRoleExecutor();
				}
			}

			return null;
		}
	}

	private static class OAuthScopeExecutor implements MethodExecutor {
		public TypedValue execute(EvaluationContext context, Object target, Object... arguments) throws AccessException {
			String[] scopes = new String[arguments.length];
			for (int i = 0; i < arguments.length; i++) {
				scopes[i] = String.valueOf(arguments[i]);
			}
			return new TypedValue(OAuth2ExpressionUtils.hasAnyScope(
					((SecurityExpressionRoot) target).getAuthentication(), scopes));
		}
	}

	private static class OAuthClientRoleExecutor implements MethodExecutor {
		public TypedValue execute(EvaluationContext context, Object target, Object... arguments) throws AccessException {
			String[] roles = new String[arguments.length];
			for (int i = 0; i < arguments.length; i++) {
				roles[i] = String.valueOf(arguments[i]);
			}
			return new TypedValue(OAuth2ExpressionUtils.clientHasAnyRole(
					((SecurityExpressionRoot) target).getAuthentication(), roles));
		}
	}

	private static class DenyOAuthClientRoleExecutor implements MethodExecutor {
		public TypedValue execute(EvaluationContext context, Object target, Object... arguments) throws AccessException {
			return new TypedValue(!OAuth2ExpressionUtils.isOAuth(((SecurityExpressionRoot) target)
					.getAuthentication()));
		}
	}
}
