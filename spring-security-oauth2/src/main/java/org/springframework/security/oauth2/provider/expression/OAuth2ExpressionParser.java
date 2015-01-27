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
package org.springframework.security.oauth2.provider.expression;

import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.ParseException;
import org.springframework.expression.ParserContext;
import org.springframework.util.Assert;

/**
 * <p>
 * A custom {@link ExpressionParser} that automatically wraps SpEL expression with
 * {@link OAuth2SecurityExpressionMethods#throwOnError(boolean)}. This makes it simple for users to specify an
 * expression and then have it verified (providing errors) after the result of the expression is known.
 * </p>
 * <p>
 * Note: The implication is that all expressions that are parsed must return a boolean result. This expectation is
 * already true since Spring Security expects the result to be a boolean.
 * </p>
 * 
 * @author Rob Winch
 * 
 */
public class OAuth2ExpressionParser implements ExpressionParser {

	private final ExpressionParser delegate;

	public OAuth2ExpressionParser(ExpressionParser delegate) {
		Assert.notNull(delegate, "delegate cannot be null");
		this.delegate = delegate;
	}

	public Expression parseExpression(String expressionString) throws ParseException {
		return delegate.parseExpression(wrapExpression(expressionString));
	}

	public Expression parseExpression(String expressionString, ParserContext context) throws ParseException {
		return delegate.parseExpression(wrapExpression(expressionString), context);
	}

	private String wrapExpression(String expressionString) {
		return "#oauth2.throwOnError(" + expressionString + ")";
	}
}