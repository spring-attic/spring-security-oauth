package demo;

import org.junit.Test;

import org.springframework.test.context.ContextConfiguration;

import sparklr.common.AbstractIntegrationTests;

@ContextConfiguration(classes = Application.class)
public class ApplicationTests extends AbstractIntegrationTests {

	@Test
	public void contextLoads() {
	}

}
