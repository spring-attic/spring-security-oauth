package demo;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.oauth2.provider.expression.OAuth2MethodSecurityExpressionHandler;

import demo.GlobalMethodSecurityTests.GlobalSecurityConfiguration;
import sparklr.common.AbstractProtectedResourceTests;

@SpringBootTest(classes = { Application.class, GlobalSecurityConfiguration.class }, webEnvironment=WebEnvironment.RANDOM_PORT)
public class GlobalMethodSecurityTests extends AbstractProtectedResourceTests {

	@Configuration
	@EnableGlobalMethodSecurity(prePostEnabled = true, proxyTargetClass = true)
	protected static class GlobalSecurityConfiguration
			extends GlobalMethodSecurityConfiguration {

		@Override
		protected MethodSecurityExpressionHandler createExpressionHandler() {
			return new OAuth2MethodSecurityExpressionHandler();
		}

	}

}
