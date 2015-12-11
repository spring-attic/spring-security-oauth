package demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class Application {

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

		@Override
		public void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				// Just for laughs, apply OAuth protection to only 3 resources
				.requestMatchers().antMatchers("/","/admin/beans","/admin/health")
			.and()
				.authorizeRequests()
					.anyRequest().access("#oauth2.hasScope('read')");
			// @formatter:on
		}

		@Override
		public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
			resources.resourceId("sparklr");
		}

	}

	@Configuration
	@EnableAuthorizationServer
	protected static class OAuth2Config extends AuthorizationServerConfigurerAdapter {

		@Value("${oauth.paths.token:/oauth/authorize}")
		private String tokenPath = "/oauth/token";

		@Value("${oauth.paths.token_key:/oauth/token_key}")
		private String tokenKeyPath = "/oauth/token_key";

		@Value("${oauth.paths.check_token:/oauth/check_token}")
		private String checkTokenPath = "/oauth/check_token";

		@Value("${oauth.paths.authorize:/oauth/authorize}")
		private String authorizePath = "/oauth/authorize";

		@Value("${oauth.paths.confirm:/oauth/confirm_access}")
		private String confirmPath = "/oauth/confirm_access";

		@Autowired
		private AuthenticationManager authenticationManager;

		@Autowired
		private ServerProperties server;

		@Override
		public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
			oauthServer.checkTokenAccess("hasRole('ROLE_TRUSTED_CLIENT')");
		}

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			String prefix = server.getServletPrefix();
			endpoints.prefix(prefix);
			// @formatter:off	
			endpoints.authenticationManager(authenticationManager)
				.pathMapping("/oauth/confirm_access", confirmPath)
				.pathMapping("/oauth/token", tokenPath)
				.pathMapping("/oauth/check_token", checkTokenPath)
				.pathMapping("/oauth/token_key", tokenKeyPath)
				.pathMapping("/oauth/authorize", authorizePath);
			// @formatter:on
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			// @formatter:off
		 	clients.inMemory()
		        .withClient("my-trusted-client")
		            .authorizedGrantTypes("password", "authorization_code", "refresh_token", "implicit")
		            .authorities("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT")
		            .scopes("read", "write", "trust")
		            .resourceIds("sparklr")
		            .accessTokenValiditySeconds(60)
 		    .and()
		        .withClient("my-client-with-registered-redirect")
		            .authorizedGrantTypes("authorization_code")
		            .authorities("ROLE_CLIENT")
		            .scopes("read", "trust")
		            .resourceIds("sparklr")
		            .redirectUris("http://anywhere?key=value")
 		    .and()
		        .withClient("my-client-with-secret")
		            .authorizedGrantTypes("client_credentials", "password")
		            .authorities("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT")
		            .scopes("read")
		            .resourceIds("sparklr")
		            .secret("secret");
		// @formatter:on
		}

	}

}
