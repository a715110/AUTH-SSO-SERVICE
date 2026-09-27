package com.dodaso.ecosystem.user.auth.sso.launcher;

import java.util.List;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Backs the "dodaso.apps" list in application.yml -- see the example block
 * in the README/comment at the bottom of this file for what to add there.
 *
 * Static/config-file-backed by design, per the "same list for everyone, for
 * now" decision: this is intentionally NOT a database table yet. Migrating
 * it into IAMS's schema later (role/page_access already exist there and are
 * a natural fit) means replacing this class's data source, not the
 * controller that consumes it -- AppLauncherController only depends on
 * List&lt;AppEntry&gt;, not on how it's populated.
 */
@Setter
@Getter
@Component
@ConfigurationProperties(prefix = "dodaso")
public class AppRegistryProperties {

  private List<AppEntry> apps = List.of();

}

/*
Add to the AuthServer's application.yml (or application-local.yml, etc.):

dodaso:
  apps:
    - name: ELCM
      description: Enterprise Lease Contract Management
      icon-url: /images/elcm-icon.png
      url: https://localhost/elcm/dashboard
      required-authority:            # blank/omitted = visible to everyone
    - name: ECWS
      description: Enterprise Collaborative Workflow System
      icon-url: /images/ecws-icon.png
      url: https://localhost/ecws/dashboard
      required-authority:

@ConfigurationProperties binds kebab-case YAML keys (icon-url, required-authority)
to the record's camelCase components (iconUrl, requiredAuthority) automatically --
no extra mapping needed.
*/