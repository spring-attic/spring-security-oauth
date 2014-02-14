package org.springframework.security.oauth.examples.sparklr.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.http.MediaType;
import org.springframework.security.oauth.examples.sparklr.PhotoInfo;
import org.springframework.security.oauth.examples.sparklr.PhotoService;
import org.springframework.security.oauth.examples.sparklr.impl.PhotoServiceImpl;
import org.springframework.security.oauth.examples.sparklr.mvc.AccessConfirmationController;
import org.springframework.security.oauth.examples.sparklr.mvc.PhotoController;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.web.accept.ContentNegotiationManagerFactoryBean;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.ViewResolver;
import org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.web.servlet.view.ContentNegotiatingViewResolver;
import org.springframework.web.servlet.view.InternalResourceViewResolver;
import org.springframework.web.servlet.view.json.MappingJacksonJsonView;

@Configuration
@EnableWebMvc
public class WebMvcConfig extends WebMvcConfigurerAdapter {

	@Bean
	public static PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer() {
		return new PropertySourcesPlaceholderConfigurer();
	}

   @Bean
    public ContentNegotiatingViewResolver contentViewResolver() throws Exception {
        ContentNegotiationManagerFactoryBean contentNegotiationManager = new ContentNegotiationManagerFactoryBean();
        contentNegotiationManager.addMediaType("json", MediaType.APPLICATION_JSON);

        InternalResourceViewResolver viewResolver = new InternalResourceViewResolver();
        viewResolver.setPrefix("/WEB-INF/jsp/");
        viewResolver.setSuffix(".jsp");

        MappingJacksonJsonView defaultView = new MappingJacksonJsonView();
        defaultView.setExtractValueFromSingleKeyModel(true);

        ContentNegotiatingViewResolver contentViewResolver = new ContentNegotiatingViewResolver();
        contentViewResolver.setContentNegotiationManager(contentNegotiationManager.getObject());
        contentViewResolver.setDefaultViews(Arrays.<View>asList(new MappingJacksonJsonView()));
        contentViewResolver.setViewResolvers(Arrays.<ViewResolver>asList(viewResolver));
        contentViewResolver.setDefaultViews(Arrays.<View>asList(defaultView));
        return contentViewResolver;
    }

    @Bean
    public PhotoController photoController(PhotoService photoService) {
        PhotoController photoController = new PhotoController();
        photoController.setPhotoService(photoService);
        return photoController;
    }

    @Bean
    public AccessConfirmationController accessConfirmationController(ClientDetailsService clientDetailsService, ApprovalStore approvalStore) {
        AccessConfirmationController accessConfirmationController = new AccessConfirmationController();
        accessConfirmationController.setClientDetailsService(clientDetailsService);
        accessConfirmationController.setApprovalStore(approvalStore);
        return accessConfirmationController;
    }

    @Bean
    public PhotoServiceImpl photoServices() {
        List<PhotoInfo> photos = new ArrayList<PhotoInfo>();
        photos.add(createPhoto("1", "marissa"));
        photos.add(createPhoto("2", "paul"));
        photos.add(createPhoto("3", "marissa"));
        photos.add(createPhoto("4", "paul"));
        photos.add(createPhoto("5", "marissa"));
        photos.add(createPhoto("6", "paul"));

        PhotoServiceImpl photoServices = new PhotoServiceImpl();
        photoServices.setPhotos(photos);
        return photoServices;
    }


    private PhotoInfo createPhoto(String id, String userId) {
        PhotoInfo photo = new PhotoInfo();
        photo.setId(id);
        photo.setName("photo" + id + ".jpg");
        photo.setUserId(userId);
        photo.setResourceURL("/org/springframework/security/oauth/examples/sparklr/impl/resources/" + photo.getName());
        return photo;
    }

    @Override
    public void configureDefaultServletHandling(
            DefaultServletHandlerConfigurer configurer) {
        configurer.enable();
    }
}
