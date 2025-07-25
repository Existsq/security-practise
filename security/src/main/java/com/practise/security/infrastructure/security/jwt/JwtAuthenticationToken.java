package com.practise.security.infrastructure.security.jwt;

import java.util.Collection;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {

  private final JwtToken token;
  private final Object principal;

  /** Неаутентифицированный токен (только токен, без principal) */
  public JwtAuthenticationToken(JwtToken token) {
    super(null);
    this.token = token;
    this.principal = null;
    setAuthenticated(false);
  }

  /** Аутентифицированный токен (principal и authorities уже есть) */
  public JwtAuthenticationToken(
      UserDetails principal, JwtToken token, Collection<? extends GrantedAuthority> authorities) {
    super(authorities);
    this.token = token;
    this.principal = principal;
    setAuthenticated(true);
  }

  @Override
  public Object getCredentials() {
    return token;
  }

  @Override
  public Object getPrincipal() {
    return principal;
  }

  @Override
  public void eraseCredentials() {
    super.eraseCredentials();
  }
}
