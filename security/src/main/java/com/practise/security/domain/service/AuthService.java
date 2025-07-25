package com.practise.security.domain.service;

import com.practise.security.api.dto.CredentialsRequest;
import com.practise.security.domain.exception.UserAlreadyExistsException;
import com.practise.security.domain.model.AuthUser;
import com.practise.security.domain.model.Role;
import com.practise.security.domain.repository.RoleRepository;
import com.practise.security.infrastructure.security.jwt.JwtService;
import com.practise.security.infrastructure.security.jwt.JwtToken;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {
  private final UserService userService;
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;
  private final RoleRepository roleRepository;

  public JwtToken register(CredentialsRequest request) {
    log.info("Register attempt for email: {}", request.getEmail());
    if (userService.existsByEmail(request.getEmail())) {
      log.warn("Registration failed: user with email {} already exists", request.getEmail());
      throw new UserAlreadyExistsException("User with this email exists");
    }

    Role userRole =
        roleRepository
            .findByName("ROLE_USER")
            .orElseThrow(() -> new RuntimeException("ROLE_USER role not found in database"));

    AuthUser user = new AuthUser();
    user.setEmail(request.getEmail());
    user.setPassword(passwordEncoder.encode(request.getPassword()));
    user.setRoles(List.of(userRole));
    user.setEnabled(true);

    userService.save(user);
    log.info("User saved to database: {}", request.getEmail());

    JwtToken token = new JwtToken(jwtService.generateToken(user));
    log.debug("JWT token generated for email: {}", request.getEmail());

    log.info("Registration completed successfully for email: {}", request.getEmail());
    return token;
  }
}
