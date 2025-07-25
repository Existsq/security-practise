package com.practise.security.api.controller;

import com.practise.security.api.dto.CredentialsRequest;
import com.practise.security.domain.service.AuthService;
import com.practise.security.infrastructure.security.jwt.JwtToken;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
public class AuthController {

  private final AuthService authService;

  @PostMapping("/register")
  public ResponseEntity<?> register(@RequestBody CredentialsRequest request) {
    log.info("Registration attempt: email={}", request.getEmail());
    JwtToken token = authService.register(request);
    log.info("Registration successful");
    return ResponseEntity.ok(token);
  }

  @GetMapping("/csrf")
  public CsrfToken csrf(CsrfToken csrfToken) {
    return csrfToken;
  }
}
