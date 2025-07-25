package com.practise.gateway.model;

import java.util.Collection;
import java.util.List;
import lombok.Data;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@Data
public class AuthUser implements UserDetails, CredentialsContainer {

  private String email;

  private String password;

  private boolean enabled = true;

  private List<String> roles = List.of("USER");

  public AuthUser(String email) {
    this.email = email;
  }

  public AuthUser(String username, List<GrantedAuthority> roles) {
    this.email = username;
    this.roles = roles.stream().map(GrantedAuthority::getAuthority).toList();
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return roles.stream().map(role -> (GrantedAuthority) () -> "ROLE_" + role).toList();
  }

  @Override
  public String getPassword() {
    return password;
  }

  @Override
  public String getUsername() {
    return email;
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return enabled;
  }

  @Override
  public void eraseCredentials() {
    this.password = null;
  }
}
