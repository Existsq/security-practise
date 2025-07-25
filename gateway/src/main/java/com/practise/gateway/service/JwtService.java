package com.practise.gateway.service;

import com.practise.gateway.jwt.JwtToken;
import com.practise.gateway.model.AuthUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;
import javax.crypto.SecretKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class JwtService {

  private final SecretKey secretKey;

  public JwtService(@Value("${jwt.secret}") String secret) {
    this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
  }

  public String extractUsername(JwtToken token) {
    log.trace("Extracting username from token");
    return extractClaim(token, Claims::getSubject);
  }

  public boolean isTokenValid(JwtToken token) {
    try {
      boolean valid = !isTokenExpired(token);
      log.trace("Token self-validation result: {}", valid);
      return valid;
    } catch (Exception e) {
      log.warn("Token validation error: {}", e.getMessage());
      return false;
    }
  }

  public Date extractExpiration(JwtToken token) {
    return extractClaim(token, Claims::getExpiration);
  }

  public <T> T extractClaim(JwtToken token, Function<Claims, T> claimsResolver) {
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }

  private Claims extractAllClaims(JwtToken token) {
    log.trace("Parsing claims from token");
    return Jwts.parser()
        .verifyWith(secretKey)
        .build()
        .parseSignedClaims(token.token())
        .getPayload();
  }

  private boolean isTokenExpired(JwtToken token) {
    boolean expired = extractExpiration(token).before(new Date());
    log.trace("Token expired: {}", expired);
    return expired;
  }

  public List<String> extractRoles(JwtToken token) {
    Claims claims = extractAllClaims(token);
    Object raw = claims.get("roles");

    if (raw instanceof List<?>) {
      return ((List<?>) raw)
          .stream().filter(String.class::isInstance).map(String.class::cast).toList();
    }
    return List.of();
  }

  public UserDetails extractUserDetails(JwtToken token) {
    String username = extractUsername(token);
    List<String> authorities = extractRoles(token);

    List<GrantedAuthority> grantedAuthorities =
        authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

    log.trace("Extracted user {} with roles {}", username, authorities);

    return new AuthUser(username, grantedAuthorities);
  }
}
