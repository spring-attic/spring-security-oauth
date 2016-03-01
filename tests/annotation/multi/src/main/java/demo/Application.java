package demo;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
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

	@Bean
	protected ResourceServerConfiguration adminResources() {

		ResourceServerConfiguration resource = new ResourceServerConfiguration() {	
			// Switch off the Spring Boot @Autowired configurers
			public void setConfigurers(List<ResourceServerConfigurer> configurers) {
				super.setConfigurers(configurers);
			}
		};

		resource.setConfigurers(Arrays.<ResourceServerConfigurer> asList(new ResourceServerConfigurerAdapter() {

			@Override
			public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
				resources.resourceId("oauth2/admin");
			}

			@Override
			public void configure(HttpSecurity http) throws Exception {
				http.antMatcher("/admin/**").authorizeRequests().anyRequest()
						.access("#oauth2.hasScope('read')");
			}

		}));
		resource.setOrder(3);

		return resource;

	}

	@Bean
	protected ResourceServerConfiguration otherResources() {

		ResourceServerConfiguration resource = new ResourceServerConfiguration() {
			// Switch off the Spring Boot @Autowired configurers
			public void setConfigurers(List<ResourceServerConfigurer> configurers) {
				super.setConfigurers(configurers);
			}
		};

		resource.setConfigurers(Arrays.<ResourceServerConfigurer> asList(new ResourceServerConfigurerAdapter() {

			@Override
			public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
				resources.resourceId("oauth2/other");
			}

			@Override
			public void configure(HttpSecurity http) throws Exception {
				http.authorizeRequests().anyRequest().access("#oauth2.hasScope('trust')");
			}
		}));
		resource.setOrder(4);

		return resource;

	}

	@Configuration
	@EnableAuthorizationServer
	protected static class OAuth2Config extends AuthorizationServerConfigurerAdapter {

		@Autowired
		private AuthenticationManager authenticationManager;

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints.authenticationManager(authenticationManager);
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			// @formatter:off
		 	clients.inMemory()
		        .withClient("my-trusted-client")
		            .authorizedGrantTypes("password", "authorization_code", "refresh_token", "implicit")
		            .authorities("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT")
		            .scopes("read", "write", "trust")
		            .resourceIds("oauth2/admin")
		            .accessTokenValiditySeconds(60)
 		    .and()
		        .withClient("my-client-with-registered-redirect")
		            .authorizedGrantTypes("authorization_code")
		            .authorities("ROLE_CLIENT")
		            .scopes("read", "trust")
		            .resourceIds("oauth2/admin")
		            .redirectUris("http://anywhere?key=value")
 		    .and()
		        .withClient("my-client-with-secret")
		            .authorizedGrantTypes("client_credentials", "password")
		            .authorities("ROLE_CLIENT")
		            .scopes("read")
		            .resourceIds("oauth2/admin")
		            .secret("secret")
 		    .and()
		        .withClient("my-other-client-with-secret")
		            .authorizedGrantTypes("password")
		            .authorities("ROLE_CLIENT")
		            .scopes("read", "trust")
		            .resourceIds("oauth2/other")
		            .secret("secret");
		// @formatter:on
		}

	}

}
