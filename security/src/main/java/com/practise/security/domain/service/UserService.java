package com.practise.security.domain.service;

import com.practise.security.domain.model.AuthUser;
import com.practise.security.domain.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {
  private final UserRepository userRepository;

  public boolean existsByEmail(String email) {
    log.trace("Checking existence of user with email: {}", email);
    return userRepository.findByEmail(email).isPresent();
  }

  public void save(AuthUser user) {
    log.trace("Saving user with email: {} to database", user.getEmail());
    userRepository.save(user);
  }
}
