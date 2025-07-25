package com.practise.gateway.config;

import java.util.Arrays;
import java.util.Collections;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity.CsrfSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.FormLoginSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.HttpBasicSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.LogoutSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.RequestCacheSpec;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import reactor.core.publisher.Mono;

@Configuration
public class SecurityConfig {

  @Value("${app.base-uri}")
  private String appBaseUri;

  @Bean
  public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
    http.cors(cors -> cors.configurationSource(corsConfigurationSource()))
        .csrf(CsrfSpec::disable)
        .authorizeExchange(
            exchanges ->
                exchanges
                    .pathMatchers("/login", "/register", "/csrf", "/secured/**")
                    .permitAll()
                    .anyExchange()
                    .authenticated())
        .exceptionHandling(
            exceptionHandling ->
                exceptionHandling.authenticationEntryPoint(
                    (swe, e) ->
                        Mono.fromRunnable(
                            () -> {
                              swe.getResponse()
                                  .setStatusCode(org.springframework.http.HttpStatus.UNAUTHORIZED);
                            })))
        .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
        .requestCache(RequestCacheSpec::disable)
        .httpBasic(HttpBasicSpec::disable)
        .formLogin(FormLoginSpec::disable)
        .logout(LogoutSpec::disable);
    return http.build();
  }

  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.addAllowedHeader("X-XSRF-TOKEN");
    config.addAllowedHeader(HttpHeaders.CONTENT_TYPE);
    config.setAllowedMethods(Arrays.asList("GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"));
    config.setAllowedOrigins(Collections.singletonList(this.appBaseUri));
    config.setAllowCredentials(true);
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    return source;
  }
}
