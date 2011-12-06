package org.springframework.security.oauth2.provider.endpoint.inject;

import com.sun.jersey.api.core.HttpContext;
import com.sun.jersey.api.representation.Form;
import com.sun.jersey.server.impl.model.method.dispatch.FormDispatchProvider;
import org.springframework.security.oauth2.provider.endpoint.params.OAuth2Parameters;
import org.springframework.util.StringUtils;

import javax.ws.rs.ext.Provider;

@Provider
public class OAuth2ParametersInjectable extends AbstractInjectableProvider<OAuth2Parameters>{

	OAuth2ParametersInjectable(){
		super(OAuth2Parameters.class);
	}

	@Override
	public OAuth2Parameters getValue(HttpContext context) {

		Form form = (Form) context.getProperties().get(FormDispatchProvider.FORM_PROPERTY);

		OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();

		if(null != form){
			oAuth2Parameters.setClientId(form.getFirst("client_id"));
			oAuth2Parameters.setClientSecret(form.getFirst("client_secret"));
			oAuth2Parameters.setGrantType(form.getFirst("grant_type"));
			oAuth2Parameters.setUsername(form.getFirst("username"));
			oAuth2Parameters.setPassword(form.getFirst("password"));
			oAuth2Parameters.setScope(form.getFirst("scope"));
			oAuth2Parameters.setRefreshToken(form.getFirst("refresh_token"));
		}

		return oAuth2Parameters;

	}

}
