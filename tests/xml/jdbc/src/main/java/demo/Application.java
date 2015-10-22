package demo;

import javax.servlet.Filter;
import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.SecurityProperties.User;
import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.ClientDetailsUserDetailsService;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.endpoint.WhitelabelApprovalEndpoint;
import org.springframework.security.oauth2.provider.endpoint.WhitelabelErrorEndpoint;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Configuration
@EnableAutoConfiguration
@RestController
@ImportResource("classpath:/context.xml")
public class Application {


	@Autowired
	private DataSource dataSource;

	@Autowired
	private SecurityProperties security;

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}
	
	@RequestMapping("/")
	public String home() {
		return "Hello World";
	}

	@Configuration
	protected static class ResourceServer extends WebSecurityConfigurerAdapter {

		@Autowired
		@Qualifier("resourceFilter")
		private Filter resourceFilter;

		@Bean
		public FilterRegistrationBean resourceFilterRegistration() {
			FilterRegistrationBean bean = new FilterRegistrationBean();
			bean.setFilter(resourceFilter);
			bean.setEnabled(false);
			return bean;
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off	
			http.addFilterBefore(resourceFilter, AbstractPreAuthenticatedProcessingFilter.class)
				.requestMatcher(new NegatedRequestMatcher(new AntPathRequestMatcher("/oauth/**")))
				.authorizeRequests().anyRequest().authenticated().expressionHandler(new OAuth2WebSecurityExpressionHandler())
			.and()
				.anonymous().disable()
				.csrf().disable()
				.exceptionHandling()
					.authenticationEntryPoint(new OAuth2AuthenticationEntryPoint())
					.accessDeniedHandler(new OAuth2AccessDeniedHandler());
			// @formatter:on
		}

	}

	@Configuration
	protected static class OAuth2Config {

		@Autowired
		private DataSource dataSource;

		@Bean
		public JdbcClientDetailsService clientDetailsService() {
			return new JdbcClientDetailsService(dataSource);
		}

		@Bean
		public JdbcTokenStore tokenStore() {
			return new JdbcTokenStore(dataSource);
		}

		@Bean
		protected AuthorizationCodeServices authorizationCodeServices() {
			return new JdbcAuthorizationCodeServices(dataSource);
		}

		@Bean
		public DefaultTokenServices tokenServices() {
			DefaultTokenServices services = new DefaultTokenServices();
			services.setClientDetailsService(clientDetailsService());
			services.setSupportRefreshToken(true);
			services.setTokenStore(tokenStore());
			return services;
		}

		@Bean
		public WhitelabelErrorEndpoint oauth2ErrorEndpoint() {
			return new WhitelabelErrorEndpoint();
		}

		@Bean
		public WhitelabelApprovalEndpoint oauth2ApprovalEndpoint() {
			return new WhitelabelApprovalEndpoint();
		}

	}

	@Configuration
	@Order(Ordered.HIGHEST_PRECEDENCE)
	protected static class TokenEndpointSecurity extends WebSecurityConfigurerAdapter {

		@Autowired
		private ClientDetailsService clientDetailsService;

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth.userDetailsService(clientDetailsUserService());
		}

		@Bean
		protected UserDetailsService clientDetailsUserService() {
			return new ClientDetailsUserDetailsService(clientDetailsService);
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http.anonymous().disable()
				.antMatcher("/oauth/token")
				.authorizeRequests().anyRequest().authenticated()
			.and()
				.httpBasic().authenticationEntryPoint(authenticationEntryPoint())
			.and()
				.csrf().requireCsrfProtectionMatcher(new AntPathRequestMatcher("/oauth/token")).disable()
				.exceptionHandling().accessDeniedHandler(accessDeniedHandler())
			.and()
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
			// @formatter:on
		}

		@Bean
		protected AccessDeniedHandler accessDeniedHandler() {
			return new OAuth2AccessDeniedHandler();
		}

		@Bean
		protected AuthenticationEntryPoint authenticationEntryPoint() {
			OAuth2AuthenticationEntryPoint entryPoint = new OAuth2AuthenticationEntryPoint();
			entryPoint.setTypeName("Basic");
			entryPoint.setRealmName("oauth2/client");
			return entryPoint;
		}

	}

	@Autowired
	public void init(AuthenticationManagerBuilder auth) throws Exception {
		User user = security.getUser();
		// @formatter:off
		auth.jdbcAuthentication().dataSource(dataSource)
			.withUser(user.getName())
			.password(user.getPassword())
			.roles(user.getRole().toArray(new String[0]));
		// @formatter:on
	}

}
