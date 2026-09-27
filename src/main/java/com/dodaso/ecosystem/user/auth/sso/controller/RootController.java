package com.dodaso.ecosystem.user.auth.sso.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class RootController {
  @GetMapping("/")
  public String root() {
    // Either show a small page with a link back to the client,
    // or just send them back to the client app.
    //return "redirect:https://localhost:443/";
    return "redirect:/apps";
  }
}