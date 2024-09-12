package application.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class UserController {

    @GetMapping("/landing")
    @ResponseBody
    public String getLandingPage() {
        return "Welcome to the landing page!";
    }

    @GetMapping("/login")
    public String getLoginPage() {
        return "login";
    }

    @GetMapping("/user")
    @ResponseBody
    public String getUserPage() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        return "Welcome, " + username + ", to the user page!";
    }

    @GetMapping("/admin")
    @ResponseBody
    public String getAdminPage() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        return "Welcome, " + username + ", to the Admin page!";
    }

    @GetMapping("/403")
    public String errorPage() {
        return "403";
    }
}
