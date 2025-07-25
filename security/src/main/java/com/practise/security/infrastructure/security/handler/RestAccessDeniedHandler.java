package com.practise.security.infrastructure.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.practise.security.api.dto.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class RestAccessDeniedHandler implements AccessDeniedHandler {

  private final ObjectMapper objectMapper;

  public RestAccessDeniedHandler(ObjectMapper objectMapper) {
    this.objectMapper = objectMapper;
  }

  @Override
  public void handle(
      HttpServletRequest request,
      HttpServletResponse response,
      AccessDeniedException accessDeniedException)
      throws IOException {
    log.warn(
        "Access denied: {} - Request URI: {}",
        accessDeniedException.getMessage(),
        request.getRequestURI());

    response.setContentType("application/json");
    response.setStatus(HttpStatus.FORBIDDEN.value());

    ErrorResponse apiError =
        new ErrorResponse(
            "Access Denied",
            accessDeniedException.getMessage() != null
                ? accessDeniedException.getMessage()
                : "Forbidden");

    String json = objectMapper.writeValueAsString(apiError);

    response.getWriter().write(json);
  }
}
