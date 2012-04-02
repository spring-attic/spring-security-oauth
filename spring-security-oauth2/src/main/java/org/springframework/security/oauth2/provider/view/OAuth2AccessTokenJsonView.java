/**
 * 
 */
package org.springframework.security.oauth2.provider.view;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessTokenSerializer;
import org.springframework.web.servlet.view.AbstractView;

/**
 * 
 * Spring MVC View that 
 * 
 * @author jricher
 *
 */
public class OAuth2AccessTokenJsonView extends AbstractView {

	/**
	 * Looks for the OAuth2AccessToken as the member "token" inside the model map and uses the serializer to write this to the response stream.
	 */
	@Override
	protected void renderMergedOutputModel(Map<String, Object> model, HttpServletRequest request, HttpServletResponse response) throws Exception {

		OAuth2AccessTokenSerializer serializer = new OAuth2AccessTokenSerializer();
		
		OAuth2AccessToken token = (OAuth2AccessToken) model.get("token");
		
		serializer.serialize(token, jgen, provider);
		

	}

}
