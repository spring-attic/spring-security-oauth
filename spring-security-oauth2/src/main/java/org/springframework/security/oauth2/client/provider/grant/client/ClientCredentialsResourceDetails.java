package org.springframework.security.oauth2.client.provider.grant.client;

import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;

/**
 * @author Dave Syer
 */
public class ClientCredentialsResourceDetails extends BaseOAuth2ProtectedResourceDetails {
	
	public ClientCredentialsResourceDetails() {
		setGrantType("client_credentials");
	}

}
