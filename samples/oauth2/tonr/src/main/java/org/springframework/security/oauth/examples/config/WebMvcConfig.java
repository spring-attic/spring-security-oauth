package org.springframework.security.oauth.examples.config;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.annotation.Resource;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.context.support.ConversionServiceFactoryBean;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.http.MediaType;
import org.springframework.http.converter.BufferedImageHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJacksonHttpMessageConverter;
import org.springframework.security.oauth.examples.tonr.SparklrService;
import org.springframework.security.oauth.examples.tonr.converter.AccessTokenRequestConverter;
import org.springframework.security.oauth.examples.tonr.impl.SparklrServiceImpl;
import org.springframework.security.oauth.examples.tonr.mvc.FacebookController;
import org.springframework.security.oauth.examples.tonr.mvc.SparklrController;
import org.springframework.security.oauth.examples.tonr.mvc.SparklrRedirectController;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.config.annotation.web.configuration.OAuth2ClientConfiguration;
import org.springframework.web.accept.ContentNegotiationManagerFactoryBean;
import org.springframework.web.client.RestOperations;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.ViewResolver;
import org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.web.servlet.view.ContentNegotiatingViewResolver;
import org.springframework.web.servlet.view.InternalResourceViewResolver;
import org.springframework.web.servlet.view.json.MappingJacksonJsonView;

@Configuration
@EnableWebMvc
@PropertySource("classpath:sparklr.properties")
public class WebMvcConfig extends WebMvcConfigurerAdapter {

	@Bean
	public static PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer() {
		return new PropertySourcesPlaceholderConfigurer();
	}

	@Bean
	public ContentNegotiatingViewResolver contentViewResolver() throws Exception {
		ContentNegotiatingViewResolver contentViewResolver = new ContentNegotiatingViewResolver();
		ContentNegotiationManagerFactoryBean contentNegotiationManager = new ContentNegotiationManagerFactoryBean();
		contentNegotiationManager.addMediaType("json", MediaType.APPLICATION_JSON);
		contentViewResolver.setContentNegotiationManager(contentNegotiationManager.getObject());
		contentViewResolver.setDefaultViews(Arrays.<View> asList(new MappingJacksonJsonView()));
		return contentViewResolver;
	}

	@Bean
	public ViewResolver viewResolver() {
		InternalResourceViewResolver viewResolver = new InternalResourceViewResolver();
		viewResolver.setPrefix("/WEB-INF/jsp/");
		viewResolver.setSuffix(".jsp");
		return viewResolver;
	}

	@Override
	public void configureDefaultServletHandling(DefaultServletHandlerConfigurer configurer) {
		configurer.enable();
	}

	@Bean
	public SparklrController sparklrController(@Qualifier("sparklrService")
	SparklrService sparklrService) {
		SparklrController controller = new SparklrController();
		controller.setSparklrService(sparklrService);
		return controller;
	}

	@Bean
	public SparklrRedirectController sparklrRedirectController(@Qualifier("sparklrRedirectService")
	SparklrService sparklrService) {
		SparklrRedirectController controller = new SparklrRedirectController();
		controller.setSparklrService(sparklrService);
		return controller;
	}

	@Bean
	public FacebookController facebookController(@Qualifier("facebookRestTemplate")
	RestOperations facebookRestTemplate) {
		FacebookController controller = new FacebookController();
		controller.setFacebookRestTemplate(facebookRestTemplate);
		return controller;
	}

	@Bean
	public SparklrServiceImpl sparklrService(@Value("${sparklrPhotoListURL}")
	String sparklrPhotoListURL, @Value("${sparklrPhotoURLPattern}")
	String sparklrPhotoURLPattern, @Value("${sparklrTrustedMessageURL}")
	String sparklrTrustedMessageURL, @Qualifier("sparklrRestTemplate")
	RestOperations sparklrRestTemplate, @Qualifier("trustedClientRestTemplate")
	RestOperations trustedClientRestTemplate) {
		SparklrServiceImpl sparklrService = new SparklrServiceImpl();
		sparklrService.setSparklrPhotoListURL(sparklrPhotoListURL);
		sparklrService.setSparklrPhotoURLPattern(sparklrPhotoURLPattern);
		sparklrService.setSparklrTrustedMessageURL(sparklrTrustedMessageURL);
		sparklrService.setSparklrRestTemplate(sparklrRestTemplate);
		sparklrService.setTrustedClientRestTemplate(trustedClientRestTemplate);
		return sparklrService;
	}

	@Bean
	public SparklrServiceImpl sparklrRedirectService(@Value("${sparklrPhotoListURL}")
	String sparklrPhotoListURL, @Value("${sparklrPhotoURLPattern}")
	String sparklrPhotoURLPattern, @Value("${sparklrTrustedMessageURL}")
	String sparklrTrustedMessageURL, @Qualifier("sparklrRedirectRestTemplate")
	RestOperations sparklrRestTemplate, @Qualifier("trustedClientRestTemplate")
	RestOperations trustedClientRestTemplate) {
		SparklrServiceImpl sparklrService = new SparklrServiceImpl();
		sparklrService.setSparklrPhotoListURL(sparklrPhotoListURL);
		sparklrService.setSparklrPhotoURLPattern(sparklrPhotoURLPattern);
		sparklrService.setSparklrTrustedMessageURL(sparklrTrustedMessageURL);
		sparklrService.setSparklrRestTemplate(sparklrRestTemplate);
		sparklrService.setTrustedClientRestTemplate(trustedClientRestTemplate);
		return sparklrService;
	}

	@Bean
	public ConversionServiceFactoryBean conversionService() {
		ConversionServiceFactoryBean conversionService = new ConversionServiceFactoryBean();
		conversionService.setConverters(Collections.singleton(new AccessTokenRequestConverter()));
		return conversionService;
	}

	public void addResourceHandlers(ResourceHandlerRegistry registry) {
		registry.addResourceHandler("/resources/**").addResourceLocations("/resources/");
	}

	@Override
	public void configureMessageConverters(List<HttpMessageConverter<?>> converters) {
		converters.add(new BufferedImageHttpMessageConverter());
	}

	@Configuration
	@Import(OAuth2ClientConfiguration.class)
	protected static class ResourceConfiguration {

		@Value("${accessTokenUri}")
		private String accessTokenUri;

		@Value("${userAuthorizationUri}")
		private String userAuthorizationUri;

		@Resource
		@Qualifier("accessTokenRequest")
		private AccessTokenRequest accessTokenRequest;

		@Bean
		public OAuth2ProtectedResourceDetails sparklr() {
			AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
			details.setId("sparklr/tonr");
			details.setClientId("tonr");
			details.setClientSecret("secret");
			details.setAccessTokenUri(accessTokenUri);
			details.setUserAuthorizationUri(userAuthorizationUri);
			details.setScope(Arrays.asList("read", "write"));
			return details;
		}

		@Bean
		public OAuth2ProtectedResourceDetails sparklrRedirect() {
			AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
			details.setId("sparklr/tonr-redirect");
			details.setClientId("tonr-with-redirect");
			details.setClientSecret("secret");
			details.setAccessTokenUri(accessTokenUri);
			details.setUserAuthorizationUri(userAuthorizationUri);
			details.setScope(Arrays.asList("read", "write"));
			details.setUseCurrentUri(false);
			return details;
		}

		@Bean
		public OAuth2ProtectedResourceDetails facebook() {
			AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
			details.setId("facebook");
			details.setClientId("233668646673605");
			details.setClientSecret("33b17e044ee6a4fa383f46ec6e28ea1d");
			details.setAccessTokenUri("https://graph.facebook.com/oauth/access_token");
			details.setUserAuthorizationUri("https://www.facebook.com/dialog/oauth");
			details.setTokenName("oauth_token");
			details.setAuthenticationScheme(AuthenticationScheme.query);
			details.setClientAuthenticationScheme(AuthenticationScheme.form);
			return details;
		}

		@Bean
		public OAuth2ProtectedResourceDetails trusted() {
			ClientCredentialsResourceDetails details = new ClientCredentialsResourceDetails();
			details.setId("sparklr/trusted");
			details.setClientId("my-client-with-registered-redirect");
			details.setAccessTokenUri(accessTokenUri);
			details.setScope(Arrays.asList("trust"));
			return details;
		}

		@Bean
		@Scope(value = "session", proxyMode = ScopedProxyMode.INTERFACES)
		public OAuth2RestTemplate facebookRestTemplate() {
			OAuth2RestTemplate template = new OAuth2RestTemplate(facebook(), new DefaultOAuth2ClientContext(
					accessTokenRequest));
			MappingJacksonHttpMessageConverter converter = new MappingJacksonHttpMessageConverter();
			converter.setSupportedMediaTypes(Arrays.asList(MediaType.APPLICATION_JSON,
					MediaType.valueOf("text/javascript")));
			template.setMessageConverters(Arrays.<HttpMessageConverter<?>> asList(converter));
			return template;
		}

		@Bean
		@Scope(value = "session", proxyMode = ScopedProxyMode.INTERFACES)
		public OAuth2RestTemplate sparklrRestTemplate() {
			return new OAuth2RestTemplate(sparklr(), new DefaultOAuth2ClientContext(accessTokenRequest));
		}

		@Bean
		@Scope(value = "session", proxyMode = ScopedProxyMode.INTERFACES)
		public OAuth2RestTemplate sparklrRedirectRestTemplate() {
			return new OAuth2RestTemplate(sparklrRedirect(), new DefaultOAuth2ClientContext(accessTokenRequest));
		}

		@Bean
		public OAuth2RestTemplate trustedClientRestTemplate() {
			return new OAuth2RestTemplate(trusted(), new DefaultOAuth2ClientContext());
		}

	}

}
