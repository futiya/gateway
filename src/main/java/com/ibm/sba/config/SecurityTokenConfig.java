package com.ibm.sba.config;

import javax.servlet.http.HttpServletResponse;

import com.ibm.sba.filter.JwtTokenAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@EnableWebSecurity    // Enable security config. This annotation denotes config for spring security.
public class SecurityTokenConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private JwtConfig jwtConfig;

    @Override
    public void configure(WebSecurity web) {
        final String[] SWAGGER_UI = {"/swagger-resources/**", "/swagger-ui.html", "/v2/api-docs", "/webjars/**",
                "/actuator/**", "/account/v2/api-docs"};

        web.ignoring().antMatchers(SWAGGER_UI);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .cors().and()
                .csrf().disable()
                // make sure we use stateless session; session won't be used to store user's state.
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                // handle an authorized attempts
                .exceptionHandling().authenticationEntryPoint((req, rsp, e) -> rsp.sendError(HttpServletResponse.SC_UNAUTHORIZED))
                .and()
                // Add a filter to validate the tokens with every request
                .addFilterAfter(new JwtTokenAuthenticationFilter(jwtConfig), UsernamePasswordAuthenticationFilter.class)
                // authorization requests config
                .authorizeRequests()
                // allow all who are accessing "auth" service
                .antMatchers(HttpMethod.POST, jwtConfig.getUri()).permitAll()
                // .antMatchers(HttpMethod.GET, "/user/api/v1/getUser/").permitAll()
                .antMatchers(HttpMethod.GET, "/course/api/v1/mentor/listAll").permitAll()
                .antMatchers(HttpMethod.POST, "/user/api/v1/create").permitAll()
                .antMatchers(HttpMethod.POST, "/course/api/v1/mentor/book").hasRole("user")
                .antMatchers(HttpMethod.GET, "/course/api/v1/user/**").hasRole("user")
                .antMatchers(HttpMethod.POST, "/course/api/v1/user/**").hasRole("user")
                .antMatchers(HttpMethod.GET, "/course/api/v1/mentor/searchcourse").hasRole("user")
                .antMatchers(HttpMethod.POST, "/course/api/v1/addrate").hasRole("user")
                // must be an admin if trying to access admin area (authentication is also required here)
                .antMatchers("/account/**", "/course/**", "/mentor/**").hasAnyRole("admin", "mentor")
//		   .antMatchers(HttpMethod.POST, "/course/**", "/account/**").hasAnyRole("admin","mentor")
                // Any other request must be authenticated
                .anyRequest().authenticated();
    }

    @Bean
    public JwtConfig jwtConfig() {
        return new JwtConfig();
    }
}
