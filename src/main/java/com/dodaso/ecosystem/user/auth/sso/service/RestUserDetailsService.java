package com.dodaso.ecosystem.user.auth.sso.service;

import com.dodaso.ecosystem.auth.container.UserDTOContainer;
import com.dodaso.ecosystem.auth.dto.UserDTO;
import com.dodaso.ecosystem.user.auth.sso.client.IAMSRestClient;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class RestUserDetailsService implements UserDetailsService {
  private final IAMSRestClient iamsRestClient;

  public RestUserDetailsService(IAMSRestClient iamsRestClient) {
    this.iamsRestClient = iamsRestClient;
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    log.debug("Loading user: {}", username);

    UserDTOContainer userDTOContainer = iamsRestClient.fetchUser(username);

    if (userDTOContainer == null) {
      log.warn("User not found: {}", username);
      throw new UsernameNotFoundException("User not found: " + username);
    }

    UserDTO userDTO = userDTOContainer.getUserDTO();
    // Convert DTO to UserDetails
    //    List<GrantedAuthority> authorities = userDTOContainer.getRoles().stream()
    //        .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
    //        .collect(Collectors.toList());

    // Decode the password hash if it was Base64 encoded for JSON transport
    String passwordHash = userDTO.getPasswordHash();

    return User.builder()
        .username(userDTO.getLoginId())
        .password(passwordHash) // Should already be BCrypt encoded from REST API
        //.authorities(authorities)
        //.accountExpired(!userDto.isAccountNonExpired())
        //.accountLocked(!userDto.isAccountNonLocked())
        //.credentialsExpired(!userDto.isCredentialsNonExpired())
        //.disabled(!userDto.isEnabled())
        //.authorities(authorities)
        .accountExpired(false)
        .accountLocked(false)
        .credentialsExpired(false)
        .disabled(false)
        .build();
  }

  private String decodePasswordHash(String encodedPasswordHash) {
    if (encodedPasswordHash == null || encodedPasswordHash.isEmpty()) {
      return null;
    }

    try {
      // Check if it's already a BCrypt hash (starts with $2a$, $2b$, $2y$)
      if (encodedPasswordHash.startsWith("$2") && encodedPasswordHash.length() == 60) {
        log.debug("Password hash is already in BCrypt format");
        return encodedPasswordHash;
      }

      // Try to decode from Base64
      byte[] decodedBytes = Base64.getDecoder().decode(encodedPasswordHash);
      String decodedHash = new String(decodedBytes, StandardCharsets.UTF_8);

      log.debug("Successfully decoded Base64 password hash");
      return decodedHash;

    } catch (IllegalArgumentException e) {
      log.warn("Failed to decode Base64 password hash, using as-is: {}", e.getMessage());
      // If Base64 decoding fails, assume it's already in plain format
      return encodedPasswordHash;
    }
  }
}