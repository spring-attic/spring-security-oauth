package org.springframework.security.access.oauth;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.expression.*;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth.provider.OAuthAuthenticationDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import java.util.Collection;
import java.util.List;
import java.util.Set;

/**
 * @author Ryan Heaton
 */
public class OAuthMethodSecurityExpressionHandler extends DefaultMethodSecurityExpressionHandler {

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
    else if (authentication.getDetails() instanceof OAuthAuthenticationDetails) {
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

  public static boolean isOAuthClientAuth(SecurityExpressionRoot root) {
    Authentication authentication = root.getAuthentication();
    if (authentication instanceof OAuth2Authentication) {
      return true;
    }
    else if (authentication.getDetails() instanceof OAuthAuthenticationDetails) {
      return true;
    }

    return false;
  }

  private static class OAuthMethodResolver implements MethodResolver {
    public MethodExecutor resolve(EvaluationContext context, Object targetObject, String name, List<TypeDescriptor> argumentTypes) throws AccessException {
      if (targetObject instanceof SecurityExpressionRoot) {
        if ("oauthClientHasRole".equals(name) || "oauthClientHasAnyRole".equals(name) || "oauthConsumerHasRole".equals(name) ||"oauthConsumerHasAnyRole".equals(name)) {
          return new OAuthClientRoleExecutor();
        }
        else if ("denyOAuthConsumer".equals(name) || "denyOAuthClient".equals(name)) {
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
