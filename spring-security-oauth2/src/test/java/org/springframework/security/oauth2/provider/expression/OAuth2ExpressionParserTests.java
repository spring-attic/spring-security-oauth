package org.springframework.security.oauth2.provider.expression;

import static org.mockito.Mockito.verify;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.ParserContext;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author Rob Winch
 */
@RunWith(MockitoJUnitRunner.class)
class OAuth2ExpressionParserTests {

    @Mock
    private ExpressionParser delegate;

    @Mock
    private ParserContext parserContext;

    private final String expressionString = "ORIGIONAL";

    private final String wrappedExpression = "#oauth2.throwOnError(" + expressionString + ")";

    private OAuth2ExpressionParser parser;

    @BeforeEach
    void setUp() {
        parser = new OAuth2ExpressionParser(delegate);
    }

    @Test
    void constructorNull() {
        assertThrows(IllegalArgumentException.class, () -> {
            new OAuth2ExpressionParser(null);
        });
    }

    @Test
    void parseExpression() {
        parser.parseExpression(expressionString);
        verify(delegate).parseExpression(wrappedExpression);
    }

    @Test
    void parseExpressionWithContext() {
        parser.parseExpression(expressionString, parserContext);
        verify(delegate).parseExpression(wrappedExpression, parserContext);
    }
}
