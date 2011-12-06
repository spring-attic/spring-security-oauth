package org.springframework.security.oauth2.provider.error;

import org.springframework.security.oauth2.common.DefaultOAuth2SerializationService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2SerializationService;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.CacheControl;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

@Provider
public class JerseyExceptionMapper implements ExceptionMapper<OAuth2Exception> {

	private final OAuth2SerializationService serializationService = new DefaultOAuth2SerializationService();

	@Context
	HttpServletResponse response;

	public Response toResponse(OAuth2Exception e) {

		CacheControl cacheControl = new CacheControl();
		cacheControl.setNoStore(true);

		response.addHeader(HttpHeaders.WWW_AUTHENTICATE, OAuth2AccessToken.BEARER_TYPE);

		return Response.status(e.getHttpErrorCode())
					   .cacheControl(cacheControl)
					   .type(MediaType.APPLICATION_JSON)
					   .entity(serializationService.serialize(e))
					   .build();

	}
}
