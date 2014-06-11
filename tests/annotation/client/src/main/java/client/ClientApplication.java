package client;

import java.util.List;
import java.util.Map;

import javax.annotation.Resource;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Configuration
@EnableAutoConfiguration
@EnableOAuth2Client
@RestController
public class ClientApplication {

	public static void main(String[] args) {
		SpringApplication.run(ClientApplication.class, args);
	}

	@Value("${oauth.resource:http://localhost:8080}")
	private String baseUrl;

	@Value("${oauth.authorize:http://localhost:8080/oauth/authorize}")
	private String authorizeUrl;

	@Value("${oauth.token:http://localhost:8080/oauth/token}")
	private String tokenUrl;
	
	@Resource
	@Qualifier("accessTokenRequest")
	private AccessTokenRequest accessTokenRequest;

	@RequestMapping("/")
	public List<Map<String,?>> home() {
		@SuppressWarnings("unchecked")
		List<Map<String,?>> result = restTemplate().getForObject(baseUrl + "/admin/beans", List.class);
		return result;
	}
	
	@Bean
	@Scope(value = "session", proxyMode = ScopedProxyMode.INTERFACES)
	public OAuth2RestOperations restTemplate() {
		return new OAuth2RestTemplate(resource(), new DefaultOAuth2ClientContext(accessTokenRequest));
	}

	@Bean
	protected OAuth2ProtectedResourceDetails resource() {
		AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();
		resource.setAccessTokenUri(tokenUrl);
		resource.setUserAuthorizationUri(authorizeUrl);
		resource.setClientId("my-trusted-client");
		return resource ;
	}
	
}
