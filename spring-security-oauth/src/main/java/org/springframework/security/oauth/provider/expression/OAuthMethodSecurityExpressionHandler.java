package org.springframework.security.oauth.provider.expression;

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
import org.springframework.security.oauth.provider.OAuthAuthenticationDetails;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class OAuthMethodSecurityExpressionHandler extends DefaultMethodSecurityExpressionHandler {

	@Override
	public StandardEvaluationContext createEvaluationContextInternal(Authentication auth, MethodInvocation mi) {
		StandardEvaluationContext ec = super.createEvaluationContextInternal(auth, mi);
		ec.addMethodResolver(new OAuthMethodResolver());
		return ec;
	}

	public static boolean consumerHasAnyRole(SecurityExpressionRoot root, String... roles) {
		Authentication authentication = root.getAuthentication();
		if (authentication.getDetails() instanceof OAuthAuthenticationDetails) {
			OAuthAuthenticationDetails details = (OAuthAuthenticationDetails) authentication.getDetails();
			List<GrantedAuthority> consumerAuthorities = details.getConsumerDetails().getAuthorities();
			if (consumerAuthorities != null) {
				Set<String> roleSet = AuthorityUtils.authorityListToSet(consumerAuthorities);
				for (String role : roles) {
					if (roleSet.contains(role)) {
						return true;
					}
				}
			}
		}

		return false;
	}

	public static boolean isOAuthConsumerAuth(SecurityExpressionRoot root) {
		Authentication authentication = root.getAuthentication();
		if (authentication.getDetails() instanceof OAuthAuthenticationDetails) {
			return true;
		}

		return false;
	}

	private static class OAuthMethodResolver implements MethodResolver {
		public MethodExecutor resolve(EvaluationContext context, Object targetObject, String name,
				List<TypeDescriptor> argumentTypes) throws AccessException {
			if (targetObject instanceof SecurityExpressionRoot) {
				if ("oauthConsumerHasRole".equals(name) || "oauthConsumerHasAnyRole".equals(name)) {
					return new OAuthClientRoleExecutor();
				} else if ("denyOAuthConsumer".equals(name)) {
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
			return new TypedValue(consumerHasAnyRole((SecurityExpressionRoot) target, roles));
		}
	}

	private static class DenyOAuthClientRoleExecutor implements MethodExecutor {
		public TypedValue execute(EvaluationContext context, Object target, Object... arguments) throws AccessException {
			return new TypedValue(!isOAuthConsumerAuth((SecurityExpressionRoot) target));
		}
	}
}
