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

package org.springframework.security.oauth2.client.filter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * Convenience filter that can be used to combine multiple filters into a single chain. The same code is included in
 * Spring 3.1, but provided here so we can use Spring 3.0 with OAuth2.
 * 
 * @author Dave Syer
 * 
 */
public class CompositeFilter implements Filter {

	private List<Filter> filters = new ArrayList<Filter>();

	public void setFilters(List<Filter> filters) {
		this.filters = new ArrayList<Filter>(filters);
	}

	public void destroy() {
		for (Filter filter : filters) {
			filter.destroy();
		}
	}

	public void init(FilterConfig config) throws ServletException {
		for (Filter filter : filters) {
			filter.init(config);
		}
	}

	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
			ServletException {
		new VirtualFilterChain(chain, filters).doFilter(request, response);
	}

	private static class VirtualFilterChain implements FilterChain {
		private final FilterChain originalChain;
		private final List<Filter> additionalFilters;
		private int currentPosition = 0;

		private VirtualFilterChain(FilterChain chain, List<Filter> additionalFilters) {
			this.originalChain = chain;
			this.additionalFilters = additionalFilters;
		}

		public void doFilter(final ServletRequest request, final ServletResponse response) throws IOException,
				ServletException {
			if (currentPosition == additionalFilters.size()) {
				originalChain.doFilter(request, response);
			} else {
				currentPosition++;
				Filter nextFilter = additionalFilters.get(currentPosition - 1);
				nextFilter.doFilter(request, response, this);
			}
		}

	}

}
