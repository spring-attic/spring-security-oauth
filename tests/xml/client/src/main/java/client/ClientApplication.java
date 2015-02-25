package client;

import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestOperations;

@Configuration
@EnableAutoConfiguration
@EnableOAuth2Client
@RestController
@ImportResource("classpath:/context.xml")
public class ClientApplication {

	public static void main(String[] args) {
		SpringApplication.run(ClientApplication.class, args);
	}

	@Value("${oauth.resource:http://localhost:8080}")
	private String baseUrl;
	
	@Autowired
	private RestOperations restTemplate;

	@RequestMapping("/")
	public List<Map<String,?>> home() {
		@SuppressWarnings("unchecked")
		List<Map<String,?>> result = restTemplate.getForObject(baseUrl + "/admin/beans", List.class);
		return result;
	}
	
}
