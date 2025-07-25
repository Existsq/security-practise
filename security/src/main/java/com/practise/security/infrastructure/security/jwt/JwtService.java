package com.practise.security.infrastructure.security.jwt;

import com.practise.security.domain.model.AuthUser;
import com.practise.security.domain.model.Role;
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
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class JwtService {

  @Value("${jwt.secret}")
  private String secret;

  @Value("${jwt.expiration-ms:86400000}")
  private long expiration;

  private final SecretKey secretKey;

  public JwtService(@Value("${jwt.secret}") String secret) {
    this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
  }

  public String extractUsername(JwtToken token) {
    log.trace("Extracting username from JWT token");
    return extractClaim(token, Claims::getSubject);
  }

  public boolean isTokenValid(JwtToken token) {
    try {
      boolean valid = !isTokenExpired(token);
      log.trace("JWT token validity check result: {}", valid);
      return valid;
    } catch (Exception e) {
      log.warn("JWT token validation error: {}", e.getMessage());
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
    log.trace("Parsing JWT claims");
    return Jwts.parser()
        .verifyWith(secretKey)
        .build()
        .parseSignedClaims(token.token())
        .getPayload();
  }

  private boolean isTokenExpired(JwtToken token) {
    boolean expired = extractExpiration(token).before(new Date());
    log.trace("JWT token expired: {}", expired);
    return expired;
  }

  public String generateToken(UserDetails userDetails) {
    log.trace("Generating JWT token for user '{}'", userDetails.getUsername());
    List<String> roles =
        userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();

    return Jwts.builder()
        .subject(userDetails.getUsername())
        .claim("roles", roles)
        .issuedAt(new Date())
        .expiration(new Date(System.currentTimeMillis() + expiration))
        .signWith(secretKey)
        .compact();
  }

  public List<String> extractRoles(JwtToken token) {
    Claims claims = extractAllClaims(token);
    Object raw = claims.get("roles");

    if (raw instanceof List<?>) {
      return ((List<?>) raw)
          .stream().filter(item -> item instanceof String).map(Object::toString).toList();
    }
    return List.of();
  }

  public UserDetails extractUserDetails(JwtToken token) {
    String username = extractUsername(token);
    List<String> roleNames = extractRoles(token);

    List<Role> roles = roleNames.stream().map(Role::new).collect(Collectors.toList());

    log.trace("Extracted user '{}' with roles {}", username, roleNames);

    return new AuthUser(username, roles);
  }
}
