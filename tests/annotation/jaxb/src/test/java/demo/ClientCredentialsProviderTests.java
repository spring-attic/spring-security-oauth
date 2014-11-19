package demo;

import java.util.Collection;
import java.util.List;

import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.converter.HttpMessageConverter;

import sparklr.common.AbstractClientCredentialsProviderTests;

/**
 * @author Dave Syer
 */
@SpringApplicationConfiguration(classes=Application.class)
public class ClientCredentialsProviderTests extends AbstractClientCredentialsProviderTests {

	@Override
	protected Collection<? extends HttpMessageConverter<?>> getAdditionalConverters() {
		return Converters.getJaxbConverters();
	}
	
	@Override
	protected List<ClientHttpRequestInterceptor> getInterceptors() {
		return Converters.getInterceptors();
	}

}
