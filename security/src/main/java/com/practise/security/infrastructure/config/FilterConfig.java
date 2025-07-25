package com.practise.security.infrastructure.config;

import com.practise.security.infrastructure.security.filter.JsonUsernamePasswordAuthFilter;
import com.practise.security.infrastructure.security.filter.JwtAuthenticationFilter;
import com.practise.security.infrastructure.security.handler.RestAuthenticationFailureHandler;
import com.practise.security.infrastructure.security.handler.RestAuthenticationSuccessHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;

@Configuration
@RequiredArgsConstructor
public class FilterConfig {

  private final AuthenticationManager authenticationManager;
  private final RestAuthenticationSuccessHandler successHandler;
  private final RestAuthenticationFailureHandler failureHandler;

  @Bean
  public JwtAuthenticationFilter jwtAuthenticationFilter() {
    return new JwtAuthenticationFilter(authenticationManager);
  }

  @Bean
  public JsonUsernamePasswordAuthFilter jsonUsernamePasswordAuthFilter() {
    JsonUsernamePasswordAuthFilter filter = new JsonUsernamePasswordAuthFilter();
    filter.setAuthenticationManager(authenticationManager);
    filter.setAuthenticationSuccessHandler(successHandler);
    filter.setAuthenticationFailureHandler(failureHandler);
    return filter;
  }
}
