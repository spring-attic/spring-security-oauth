package demo;

import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.oauth2.provider.expression.OAuth2MethodSecurityExpressionHandler;

import sparklr.common.AbstractProtectedResourceTests;
import demo.GlobalMethodSecurityTests.GlobalSecurityConfiguration;

@SpringApplicationConfiguration(classes = { Application.class,
		GlobalSecurityConfiguration.class })
public class GlobalMethodSecurityTests extends AbstractProtectedResourceTests {

	@Configuration
	@EnableGlobalMethodSecurity(prePostEnabled = true, proxyTargetClass = true)
	protected static class GlobalSecurityConfiguration extends
			GlobalMethodSecurityConfiguration {

		@Override
		protected MethodSecurityExpressionHandler createExpressionHandler() {
			return new OAuth2MethodSecurityExpressionHandler();
		}

	}

}
