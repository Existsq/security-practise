package com.practise.security.infrastructure.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.practise.security.api.dto.CredentialsRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

// Данный фильтр отвечает за аутентификацию пользователя
// по предоставленному логину и паролю из тела запроса
@Slf4j
public class JsonUsernamePasswordAuthFilter extends AbstractAuthenticationProcessingFilter {

  private final ObjectMapper objectMapper = new ObjectMapper();

  public JsonUsernamePasswordAuthFilter() {
    super(PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, "/login"));
  }

  @Override
  public Authentication attemptAuthentication(
      HttpServletRequest request, HttpServletResponse response)
      throws AuthenticationException, IOException {

    if (!MediaType.APPLICATION_JSON_VALUE.equals(request.getContentType())) {
      log.warn("Authentication failed: unsupported Content-Type '{}'", request.getContentType());
      throw new AuthenticationServiceException("Content type not supported");
    }

    CredentialsRequest credentialsRequest =
        objectMapper.readValue(request.getInputStream(), CredentialsRequest.class);

    String username = credentialsRequest.getEmail();
    String password = credentialsRequest.getPassword();

    log.debug("Authentication attempt for email: {}", username);

    UsernamePasswordAuthenticationToken authRequest =
        new UsernamePasswordAuthenticationToken(username, password);

    setDetails(request, authRequest);

    return this.getAuthenticationManager().authenticate(authRequest);
  }

  private void setDetails(
      HttpServletRequest request, UsernamePasswordAuthenticationToken authRequest) {
    authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
  }
}
