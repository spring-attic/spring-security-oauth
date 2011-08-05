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
public class OAuthSecurityExpressionHandler extends DefaultMethodSecurityExpressionHandler {

	@Override
	public StandardEvaluationContext createEvaluationContextInternal(Authentication auth, MethodInvocation mi) {
		StandardEvaluationContext ec = super.createEvaluationContextInternal(auth, mi);
		ec.addMethodResolver(new OAuthMethodResolver());
		return ec;
	}

	public static boolean clientHasAnyRole(SecurityExpressionRoot root, String... roles) {
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

	public static boolean clientHasAnyScope(SecurityExpressionRoot root, String... scopes) {
		Authentication authentication = root.getAuthentication();
		if (authentication.getDetails() instanceof OAuthAuthenticationDetails) {
			OAuthAuthenticationDetails details = (OAuthAuthenticationDetails) authentication.getDetails();
			List<GrantedAuthority> consumerAuthorities = details.getConsumerDetails().getAuthorities();
			if (consumerAuthorities != null) {
				Set<String> scopeSet = AuthorityUtils.authorityListToSet(consumerAuthorities);
				for (String scope : scopes) {
					if (scopeSet.contains(scope)) {
						return true;
					}
				}
			}
		}

		return false;
	}

	public static boolean isOAuthClientAuth(SecurityExpressionRoot root) {
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
				if ("oauthClientHasRole".equals(name) || "oauthClientHasAnyRole".equals(name)
						|| "oauthConsumerHasRole".equals(name) || "oauthConsumerHasAnyRole".equals(name)) {
					return new OAuthClientRoleExecutor();
				} else if ("oauthClientHasScope".equals(name) || "oauthClientHasAnyScope".equals(name)) {
					return new OAuthClientScopeExecutor();
				} else if ("denyOAuthConsumer".equals(name) || "denyOAuthClient".equals(name)) {
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

	private static class OAuthClientScopeExecutor implements MethodExecutor {
		public TypedValue execute(EvaluationContext context, Object target, Object... arguments) throws AccessException {
			String[] scopes = new String[arguments.length];
			for (int i = 0; i < arguments.length; i++) {
				scopes[i] = String.valueOf(arguments[i]);
			}
			return new TypedValue(clientHasAnyScope((SecurityExpressionRoot) target, scopes));
		}
	}

	private static class DenyOAuthClientRoleExecutor implements MethodExecutor {
		public TypedValue execute(EvaluationContext context, Object target, Object... arguments) throws AccessException {
			return new TypedValue(!isOAuthClientAuth((SecurityExpressionRoot) target));
		}
	}
}
