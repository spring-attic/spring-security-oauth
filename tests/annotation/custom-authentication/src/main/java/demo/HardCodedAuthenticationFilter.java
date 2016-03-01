package demo;

import java.io.IOException;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.util.OAuth2Utils;

/**
 * Authentication filter that would only authenticate one client, using the
 * "client_id" parameter.
 * 
 * @author mtecourt
 *
 */
public class HardCodedAuthenticationFilter implements Filter {

    private static final String AUTHORIZED_CLIENT_ID = "my-client-with-secret";
    private static final List<GrantedAuthority> CLIENT_AUTHORITIES = AuthorityUtils
            .commaSeparatedStringToAuthorityList("ROLE_CLIENT");

    private static final Logger LOGGER = LoggerFactory.getLogger("CustomAuthenticationFilter");

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // NOPE
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
            ServletException {

        String clientId = request.getParameter(OAuth2Utils.CLIENT_ID);

        if (AUTHORIZED_CLIENT_ID.equals(clientId)) {
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    AUTHORIZED_CLIENT_ID, "", CLIENT_AUTHORITIES);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            LOGGER.info("Just authenticated : {}", clientId);
        } else {
            LOGGER.info("Did NOT authenticate : {}", clientId);
        }

        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        // NOPE
    }

}
