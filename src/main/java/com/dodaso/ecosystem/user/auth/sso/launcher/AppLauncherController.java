package com.dodaso.ecosystem.user.auth.sso.launcher;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Serves the "panel of app icons" a user lands on after login when there was
 * no bookmarked deep link to replay. Reached via
 * appFilterChain's formLogin(...).defaultSuccessUrl("/apps", false) in
 * AuthServerConfig -- see the comment there for why "false" matters (it's
 * what makes this ONLY apply when there's no saved request).
 *
 * Already covered by appFilterChain's existing
 * .authorizeHttpRequests(...).anyRequest().authenticated() -- no security
 * config change needed beyond the defaultSuccessUrl line.
 */
@Controller
public class AppLauncherController {

  private final AppRegistryProperties appRegistry;

  public AppLauncherController(AppRegistryProperties appRegistry) {
    this.appRegistry = appRegistry;
  }

  @GetMapping("/apps")
  public String showLauncher(Authentication authentication, Model model) {
    // ASSUMPTION, flagged: this reads whatever GrantedAuthority values are
    // already on the Authentication principal. It does NOT know how those
    // get populated (a UserDetailsService, an IAMS-backed authorities
    // mapper, etc.) -- that wiring wasn't part of the files reviewed so
    // far. Every AppEntry has requiredAuthority left blank today, so this
    // authority set is currently unused in practice -- filtering is inert
    // until at least one entry sets a required-authority AND real
    // authorities are actually being granted at login time. Confirm the
    // latter is in place before relying on the former.
    Set<String> userAuthorities = authentication.getAuthorities().stream()
        .map(GrantedAuthority::getAuthority)
        .collect(Collectors.toSet());

    List<AppEntry> visibleApps = appRegistry.getApps().stream()
        .filter(app -> app.isVisibleTo(userAuthorities))
        .toList();

    System.out.println("visibleApps:" + visibleApps);
    model.addAttribute("apps", visibleApps);
    return "apps";
  }
}