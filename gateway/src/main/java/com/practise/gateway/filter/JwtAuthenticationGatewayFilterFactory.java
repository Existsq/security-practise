package com.practise.gateway.filter;

import com.practise.gateway.jwt.JwtAuthenticationToken;
import com.practise.gateway.jwt.JwtToken;
import com.practise.gateway.service.JwtService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class JwtAuthenticationGatewayFilterFactory extends AbstractGatewayFilterFactory<Object> {

  private final JwtService jwtService;

  public JwtAuthenticationGatewayFilterFactory(JwtService jwtService) {
    super(Object.class);
    this.jwtService = jwtService;
  }

  @Override
  public GatewayFilter apply(Object config) {
    return (exchange, chain) -> {
      ServerHttpRequest request = exchange.getRequest();

      HttpCookie tokenCookie = request.getCookies().getFirst("token");
      if (tokenCookie == null) {
        log.trace("No token cookie found");
        return chain.filter(exchange);
      }

      String tokenValue = tokenCookie.getValue();
      JwtToken token = new JwtToken(tokenValue);

      if (!jwtService.isTokenValid(token)) {
        log.warn("Invalid JWT token from cookie");
        return chain.filter(exchange);
      }

      UserDetails userDetails = jwtService.extractUserDetails(token);
      JwtAuthenticationToken authentication =
          new JwtAuthenticationToken(userDetails, token, userDetails.getAuthorities());

      log.debug("JWT authenticated for user {}", userDetails.getUsername());

      return chain
          .filter(exchange)
          .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
    };
  }
}
