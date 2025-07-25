package com.practise.security.infrastructure.security.filter;

import com.practise.security.infrastructure.security.jwt.JwtAuthenticationToken;
import com.practise.security.infrastructure.security.jwt.JwtToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  private final AuthenticationManager authenticationManager;

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

    String tokenValue = extractTokenFromCookies(request);

    if (tokenValue == null) {
      log.trace("JWT token not found in cookies");
      filterChain.doFilter(request, response);
      return;
    }

    JwtToken token = new JwtToken(tokenValue);
    JwtAuthenticationToken unauthenticatedToken = new JwtAuthenticationToken(token);

    Authentication authentication = authenticationManager.authenticate(unauthenticatedToken);
    SecurityContextHolder.createEmptyContext().setAuthentication(authentication);
    log.debug("JWT authenticated user: {}", authentication.getName());

    filterChain.doFilter(request, response);
  }

  private String extractTokenFromCookies(HttpServletRequest request) {
    if (request.getCookies() == null) return null;

    for (Cookie cookie : request.getCookies()) {
      if ("token".equals(cookie.getName())) {
        return cookie.getValue();
      }
    }
    return null;
  }
}
