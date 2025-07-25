package com.practise.security.infrastructure.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.practise.security.api.dto.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {

  private final ObjectMapper objectMapper = new ObjectMapper();

  @Override
  public void commence(
      HttpServletRequest request,
      HttpServletResponse response,
      AuthenticationException authException)
      throws IOException {
    log.warn(
        "Unauthorized access attempt: {} - Request URI: {}",
        authException.getMessage(),
        request.getRequestURI());

    ErrorResponse error = new ErrorResponse("Unauthorized", authException.getMessage());

    response.setContentType("application/json");
    response.setStatus(HttpStatus.UNAUTHORIZED.value());
    response.getWriter().write(objectMapper.writeValueAsString(error));
  }
}
