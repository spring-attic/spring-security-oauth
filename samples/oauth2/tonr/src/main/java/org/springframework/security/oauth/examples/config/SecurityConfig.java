package org.springframework.security.oauth.examples.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Bean
	public OAuth2ClientContextFilter oauth2ClientFilter() {
		OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
		return filter;
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication().withUser("marissa").password("wombat").roles("USER").and().withUser("sam")
				.password("kangaroo").roles("USER");
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/resources/**");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
    	    http.authorizeRequests()
                .antMatchers("/sparklr/**","/facebook/**").hasRole("USER")
                .anyRequest().permitAll()
                .and()
            .logout()
                .logoutSuccessUrl("/login.jsp")
                .logoutUrl("/logout.do")
                .permitAll()
                .and()
            .formLogin()
                .loginPage("/login.jsp")
                .loginProcessingUrl("/login.do")
                .failureUrl("/login.jsp?authentication_error=true")
                .usernameParameter("j_username")
                .passwordParameter("j_password")
                .permitAll();
    	// @formatter:on
	}

}
