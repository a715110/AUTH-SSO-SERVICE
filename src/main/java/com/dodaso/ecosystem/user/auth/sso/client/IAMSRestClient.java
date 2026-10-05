package com.dodaso.ecosystem.user.auth.sso.client;

import com.dodaso.ecosystem.auth.container.UserDTOContainer;
import com.dodaso.ecosystem.auth.container.UserDirectoryDTOContainer;
import com.dodaso.ecosystem.baseline.common.constant.ServiceDiscoveryEnum;
import com.dodaso.ecosystem.baseline.common.container.RESTReqContainer;
import com.dodaso.ecosystem.baseline.common.proxy.RESTServiceClient;
import com.netflix.discovery.EurekaClient;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class IAMSRestClient {

  //@Value("${iams.service.base-url}")
  //String iamsServiceBaseUrl;

  @Autowired
  private EurekaClient eurekaClient;

  @Autowired
  RESTServiceClient restServiceClient;

//  public UserDTOContainer fetchUser(String username) {
//    try {
//
//      String url = iamsServiceBaseUrl + "/userController/getUserByLoginId?loginId=" + username;
//      log.debug("Fetching user from: {}", url);
//
//      RestTemplate restTemplate = new RestTemplate(getClientHttpRequestFactory());
//      ResponseEntity<UserDTOContainer> response = restTemplate.getForEntity(url,
//          UserDTOContainer.class);
//
//      if (response.getStatusCode().is2xxSuccessful()) {
//        return response.getBody();
//      } else {
//        log.warn("Failed to fetch user {}: {}", username, response.getStatusCode());
//        return null;
//      }
//    } catch (Exception e) {
//      log.error("Error fetching user {}: {}", username, e.getMessage());
//      return null;
//    }
//  }

  public UserDTOContainer fetchUser(String username) {
    try {
      UserDTOContainer userDTOContainer = new UserDTOContainer();
      RESTReqContainer<UserDTOContainer> restReqContainer = new RESTReqContainer<>(
          ServiceDiscoveryEnum.iams_service.getServiceDiscoveryName(),
          "/userController/getUserByLoginId?loginId=" + username,
          userDTOContainer,
          new ParameterizedTypeReference<UserDTOContainer>() {
          },
          HttpMethod.GET);

      userDTOContainer = restServiceClient.callRESTService(restReqContainer);
      return userDTOContainer;
    } catch (Exception e) {
      log.error("Error fetching user {}: {}", username, e.getMessage());
      return null;
    }
  }

  /**
   * Reads the user's directory entry (roles, team, workspaces) from IAMS. Used
   * at login to build Spring Security authorities. Returns null on any failure
   * or when IAMS has no entry, so the caller can fail open to "no authorities"
   * rather than block the login.
   */
  public UserDirectoryDTOContainer fetchUserDirectory(String username) {
    try {
      RESTReqContainer<UserDirectoryDTOContainer> restReqContainer = new RESTReqContainer<>(
          ServiceDiscoveryEnum.iams_service.getServiceDiscoveryName(),
          "/userController/getUserDirectoryByLoginId?loginId=" + username,
          new UserDirectoryDTOContainer(),
          new ParameterizedTypeReference<UserDirectoryDTOContainer>() {
          },
          HttpMethod.GET);

      return restServiceClient.callRESTService(restReqContainer);
    } catch (Exception e) {
      log.error("Error fetching directory entry for {}: {}", username, e.getMessage());
      return null;
    }
  }
}