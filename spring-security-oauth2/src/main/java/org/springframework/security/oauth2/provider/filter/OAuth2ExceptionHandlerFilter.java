/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.provider.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.error.DefaultProviderExceptionHandler;
import org.springframework.security.oauth2.provider.error.ProviderExceptionHandler;
import org.springframework.security.oauth2.provider.web.DefaultOAuth2ExceptionRenderer;
import org.springframework.security.oauth2.provider.web.OAuth2ExceptionRenderer;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.servlet.mvc.support.DefaultHandlerExceptionResolver;

/**
 * Filter for handling OAuth2-specific exceptions.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class OAuth2ExceptionHandlerFilter extends GenericFilterBean {

	private ProviderExceptionHandler providerExceptionHandler = new DefaultProviderExceptionHandler();

	private DefaultHandlerExceptionResolver exceptionResolver = new DefaultHandlerExceptionResolver();

	private OAuth2ExceptionRenderer exceptionRenderer = new DefaultOAuth2ExceptionRenderer();

	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException,
			ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		try {
			chain.doFilter(request, response);

			if (logger.isDebugEnabled()) {
				logger.debug("Chain processed normally");
			}
		}
		catch (IOException ex) {
			throw ex;
		}
		catch (Exception ex) {

			try {
				ResponseEntity<OAuth2Exception> result = providerExceptionHandler.handle(ex);
				exceptionRenderer.handleHttpEntityResponse(result, new ServletWebRequest(request, response));
				response.flushBuffer();
			}
			catch (ServletException e) {
				// Re-use some of the default Spring dispatcher behaviour - the exception came from the filter chain and
				// not from an MCVC handler
				if (exceptionResolver.resolveException(request, response, this, e) == null) {
					throw e;
				}
			}
			catch (IOException e) {
				throw e;
			}
			catch (RuntimeException e) {
				throw e;
			}
			catch (Exception e) {
				// Wrap other Exceptions. These are not expected to happen
				throw new RuntimeException(e);
			}
		}
	}

	public void setProviderExceptionHandler(ProviderExceptionHandler providerExceptionHandler) {
		this.providerExceptionHandler = providerExceptionHandler;
	}
	
	public void setExceptionRenderer(OAuth2ExceptionRenderer exceptionRenderer) {
		this.exceptionRenderer = exceptionRenderer;
	}

}
