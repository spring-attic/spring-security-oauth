package demo;

import java.util.Collection;

import org.springframework.http.converter.HttpMessageConverter;

import sparklr.common.AbstractRefreshTokenSupportTests;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class RefreshTokenSupportTests extends AbstractRefreshTokenSupportTests {

	@Override
	protected Collection<? extends HttpMessageConverter<?>> getAdditionalConverters() {
		return Converters.getJaxbConverters();
	}

}
