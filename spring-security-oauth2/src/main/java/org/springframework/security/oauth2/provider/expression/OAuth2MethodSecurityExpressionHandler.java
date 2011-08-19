package org.springframework.security.oauth2.provider.expression;

import java.util.Collection;
import java.util.List;
import java.util.Set;

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
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

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

	public static boolean clientHasAnyRole(SecurityExpressionRoot root, String... roles) {
		Authentication authentication = root.getAuthentication();
		if (authentication instanceof OAuth2Authentication) {
			Authentication clientAuthentication = ((OAuth2Authentication) authentication).getClientAuthentication();
			Collection<? extends GrantedAuthority> clientAuthorities = clientAuthentication.getAuthorities();
			if (clientAuthorities != null) {
				Set<String> roleSet = AuthorityUtils.authorityListToSet(clientAuthorities);
				for (String role : roles) {
					if (roleSet.contains(role)) {
						return true;
					}
				}
			}
		}

		return false;
	}

	public static boolean isOAuthClientAuth(SecurityExpressionRoot root) {

		Authentication authentication = root.getAuthentication();
		if (authentication instanceof OAuth2Authentication) {
			return true;
		}

		return false;
	}

	private static class OAuthMethodResolver implements MethodResolver {
		public MethodExecutor resolve(EvaluationContext context, Object targetObject, String name,
				List<TypeDescriptor> argumentTypes) throws AccessException {
			if (targetObject instanceof SecurityExpressionRoot) {
				if ("oauthClientHasRole".equals(name) || "oauthClientHasAnyRole".equals(name)) {
					return new OAuthClientRoleExecutor();
				} else if ("denyOAuthClient".equals(name)) {
					return new DenyOAuthClientRoleExecutor();
				}
			}

			return null;
		}

	}

	private static class OAuthClientRoleExecutor implements MethodExecutor {
		public TypedValue execute(EvaluationContext context, Object target, Object... arguments) throws AccessException {
			String[] roles = new String[arguments.length];
			for (int i = 0; i < arguments.length; i++) {
				roles[i] = String.valueOf(arguments[i]);
			}
			return new TypedValue(clientHasAnyRole((SecurityExpressionRoot) target, roles));
		}
	}

	private static class DenyOAuthClientRoleExecutor implements MethodExecutor {
		public TypedValue execute(EvaluationContext context, Object target, Object... arguments) throws AccessException {
			return new TypedValue(!isOAuthClientAuth((SecurityExpressionRoot) target));
		}
	}
}
