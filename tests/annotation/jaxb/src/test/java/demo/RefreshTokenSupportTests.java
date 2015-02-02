package demo;

import java.util.Collection;

import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.converter.HttpMessageConverter;

import sparklr.common.AbstractRefreshTokenSupportTests;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
@SpringApplicationConfiguration(classes=Application.class)
public class RefreshTokenSupportTests extends AbstractRefreshTokenSupportTests {

	@Override
	protected Collection<? extends HttpMessageConverter<?>> getAdditionalConverters() {
		return Converters.getJaxbConverters();
	}

}
