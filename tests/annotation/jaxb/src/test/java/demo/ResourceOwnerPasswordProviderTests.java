package demo;

import java.util.Collection;

import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.converter.HttpMessageConverter;

import sparklr.common.AbstractResourceOwnerPasswordProviderTests;

/**
 * @author Dave Syer
 */
@SpringApplicationConfiguration(classes=Application.class)
public class ResourceOwnerPasswordProviderTests extends AbstractResourceOwnerPasswordProviderTests {

	@Override
	protected Collection<? extends HttpMessageConverter<?>> getAdditionalConverters() {
		return Converters.getJaxbConverters();
	}

}
