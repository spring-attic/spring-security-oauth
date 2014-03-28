package org.springframework.security.oauth2.provider.client;

import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

import org.codehaus.jackson.JsonParser;
import org.codehaus.jackson.JsonProcessingException;
import org.codehaus.jackson.JsonToken;
import org.codehaus.jackson.map.DeserializationContext;
import org.codehaus.jackson.map.deser.std.StdDeserializer;
import org.codehaus.jackson.map.type.SimpleType;
import org.codehaus.jackson.type.JavaType;
import org.codehaus.jackson.type.TypeReference;
import org.springframework.util.StringUtils;

public class JacksonArrayOrStringDeserializer extends StdDeserializer<Set<String>> {

	public JacksonArrayOrStringDeserializer() {
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