package com.practise.security.infrastructure.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.practise.security.api.dto.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class RestAuthenticationFailureHandler implements AuthenticationFailureHandler {

  private final ObjectMapper objectMapper = new ObjectMapper();

  @Override
  public void onAuthenticationFailure(
      HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
      throws IOException {

    log.warn(
        "Authentication failed: {} - Request URI: {}",
        exception.getMessage(),
        request.getRequestURI());

    ErrorResponse errorResponse = new ErrorResponse("Unauthorized", "Invalid email or password");

    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    objectMapper.writeValue(response.getWriter(), errorResponse);
  }
}
