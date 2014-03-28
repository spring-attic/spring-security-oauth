package org.springframework.security.oauth2.provider.client;

import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

import org.springframework.util.StringUtils;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.type.SimpleType;

@SuppressWarnings("serial")
public class Jackson2ArrayOrStringDeserializer extends StdDeserializer<Set<String>> {

	public Jackson2ArrayOrStringDeserializer() {
		super(Set.class);
	}

	@Override
	public JavaType getValueType() {
		return SimpleType.construct(String.class);
	}

	@Override
	public Set<String> deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException,
			JsonProcessingException {
		JsonToken token = jp.getCurrentToken();
		if (token.isScalarValue()) {
			String list = jp.getText();
			list = list.replaceAll("\\s+", ",");
			return new LinkedHashSet<String>(Arrays.asList(StringUtils.commaDelimitedListToStringArray(list)));
		}
		return jp.readValueAs(new TypeReference<Set<String>>() {
		});
	}
}