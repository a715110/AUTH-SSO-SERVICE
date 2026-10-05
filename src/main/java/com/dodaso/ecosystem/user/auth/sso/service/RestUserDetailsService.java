package com.dodaso.ecosystem.user.auth.sso.service;

import com.dodaso.ecosystem.auth.container.UserDTOContainer;
import com.dodaso.ecosystem.auth.container.UserDirectoryDTOContainer;
import com.dodaso.ecosystem.auth.dto.UserDTO;
import com.dodaso.ecosystem.user.auth.sso.client.IAMSRestClient;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
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
    // Roles come from the IAMS directory entry (UserDirectoryDTO.roleNames),
    // not from UserDTO, which carries no roles.
    List<GrantedAuthority> authorities = loadAuthorities(userDTO.getLoginId());

    // Decode the password hash if it was Base64 encoded for JSON transport
    String passwordHash = userDTO.getPasswordHash();

    return User.builder()
        .username(userDTO.getLoginId())
        .password(passwordHash) // Should already be BCrypt encoded from REST API
        .authorities(authorities)
        //.accountExpired(!userDto.isAccountNonExpired())
        //.accountLocked(!userDto.isAccountNonLocked())
        //.credentialsExpired(!userDto.isCredentialsNonExpired())
        //.disabled(!userDto.isEnabled())
        .accountExpired(false)
        .accountLocked(false)
        .credentialsExpired(false)
        .disabled(false)
        .build();
  }

  /**
   * Maps the user's IAMS role names to Spring Security authorities, e.g.
   * "Super Admin" becomes ROLE_SUPER_ADMIN. Fails open: if IAMS has no
   * directory entry or the call fails, the user logs in with no authorities
   * instead of being locked out, and AppEntry.requiredAuthority simply hides
   * any app that needs one.
   */
  private List<GrantedAuthority> loadAuthorities(String loginId) {
    List<GrantedAuthority> authorities = new ArrayList<>();
    UserDirectoryDTOContainer directory = iamsRestClient.fetchUserDirectory(loginId);
    if (directory == null || directory.getUserDirectoryDTO() == null
        || directory.getUserDirectoryDTO().getRoleNames() == null) {
      log.warn("No IAMS roles found for {}; granting no authorities", loginId);
      return authorities;
    }
    for (String roleName : directory.getUserDirectoryDTO().getRoleNames()) {
      String authority = toAuthority(roleName);
      if (authority != null) {
        authorities.add(new SimpleGrantedAuthority(authority));
      }
    }
    log.debug("Granted authorities for {}: {}", loginId, authorities);
    return authorities;
  }

  /** Upper-cases, turns every run of non-alphanumerics into one underscore, and adds ROLE_. */
  static String toAuthority(String roleName) {
    if (roleName == null || roleName.isBlank()) {
      return null;
    }
    String normalized = roleName.trim().toUpperCase(Locale.ROOT)
        .replaceAll("[^A-Z0-9]+", "_")
        .replaceAll("^_+|_+$", "");
    return normalized.isEmpty() ? null : "ROLE_" + normalized;
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