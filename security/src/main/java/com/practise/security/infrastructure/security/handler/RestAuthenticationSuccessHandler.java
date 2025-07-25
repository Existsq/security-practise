package com.practise.security.infrastructure.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.practise.security.infrastructure.security.jwt.JwtService;
import com.practise.security.infrastructure.security.jwt.JwtToken;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class RestAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

  private final JwtService jwtService;
  private final ObjectMapper objectMapper = new ObjectMapper();

  @Override
  public void onAuthenticationSuccess(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication)
      throws IOException {

    UserDetails userDetails = (UserDetails) authentication.getPrincipal();

    log.info(
        "Authentication successful for user: {} - Request URI: {}",
        userDetails.getUsername(),
        request.getRequestURI());

    JwtToken token = new JwtToken(jwtService.generateToken(userDetails));

    response.setStatus(HttpServletResponse.SC_OK);
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    objectMapper.writeValue(response.getWriter(), token);
  }
}
