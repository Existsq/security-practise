package com.practise.security.domain.service;

import com.practise.security.domain.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

  private final UserRepository userRepository;

  @Override
  public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
    log.info("Attempt to load user by email: {}", email);

    return userRepository
        .findByEmail(email)
        .orElseThrow(
            () -> {
              log.warn("User not found: {}", email);
              return new UsernameNotFoundException("User not found: " + email);
            });
  }
}
