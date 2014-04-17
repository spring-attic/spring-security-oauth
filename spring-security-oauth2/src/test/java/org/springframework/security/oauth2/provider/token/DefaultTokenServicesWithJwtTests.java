package org.springframework.security.oauth2.provider.token;


/**
 * @author Ryan Heaton
 * @author Dave Syer
 * 
 */
public class DefaultTokenServicesWithJwtTests extends AbstractDefaultTokenServicesTests {

	private JwtTokenStore tokenStore;
	JwtAccessTokenConverter enhancer = new JwtAccessTokenConverter();

	@Override
	protected TokenStore createTokenStore() {
		tokenStore = new JwtTokenStore(enhancer);
		return tokenStore;
	}
	
	@Override
	protected void configureTokenServices(DefaultTokenServices services) throws Exception {
		enhancer.afterPropertiesSet();
		services.setTokenEnhancer(enhancer);
		super.configureTokenServices(services);
	}

}
