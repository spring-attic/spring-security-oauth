package demo;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Configuration
@EnableAutoConfiguration
@RestController
public class Application {

	@Autowired
	private DataSource dataSource;

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@RequestMapping("/")
	public String home() {
		return "Hello World";
	}

	@Configuration
	@EnableResourceServer
	protected static class ResourceServer extends ResourceServerConfigurerAdapter {

		@Autowired
		private TokenStore tokenStore;

		@Override
		public void configure(ResourceServerSecurityConfigurer resources)
				throws Exception {
			resources.tokenStore(tokenStore);
		}

		@Override
		public void configure(HttpSecurity http) throws Exception {
			http.authorizeRequests().anyRequest().authenticated();
		}

	}

	@Configuration
	@EnableAuthorizationServer
	protected static class OAuth2Config extends AuthorizationServerConfigurerAdapter {

		@Autowired
		private AuthenticationManager auth;

		@Autowired
		private DataSource dataSource;

		private BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

		@Bean
		public JdbcTokenStore tokenStore() {
			return new JdbcTokenStore(dataSource);
		}

		@Bean
		protected AuthorizationCodeServices authorizationCodeServices() {
			return new JdbcAuthorizationCodeServices(dataSource);
		}

		@Override
		public void configure(AuthorizationServerSecurityConfigurer security)
				throws Exception {
			security.passwordEncoder(passwordEncoder);
		}

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints)
				throws Exception {
			endpoints.authorizationCodeServices(authorizationCodeServices())
					.authenticationManager(auth).tokenStore(tokenStore())
					.approvalStoreDisabled();
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			// @formatter:off
			clients.jdbc(dataSource)
					.passwordEncoder(passwordEncoder)
				.withClient("my-trusted-client")
					.authorizedGrantTypes("password", "authorization_code",
							"refresh_token", "implicit")
					.authorities("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT")
					.scopes("read", "write", "trust")
					.resourceIds("oauth2-resource")
					.accessTokenValiditySeconds(60).and()
				.withClient("my-client-with-registered-redirect")
					.authorizedGrantTypes("authorization_code")
					.authorities("ROLE_CLIENT").scopes("read", "trust")
					.resourceIds("oauth2-resource")
					.redirectUris("http://anywhere?key=value").and()
				.withClient("my-client-with-secret")
					.authorizedGrantTypes("client_credentials", "password")
					.authorities("ROLE_CLIENT").scopes("read")
					.resourceIds("oauth2-resource").secret("secret");
			// @formatter:on
		}

	}

	@Autowired
	public void init(AuthenticationManagerBuilder auth) throws Exception {
		// @formatter:off
			auth.jdbcAuthentication().dataSource(dataSource).withUser("dave")
					.password("secret").roles("USER");
			// @formatter:on
	}

}
