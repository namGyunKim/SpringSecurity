package io.security.basicsecurity;

import org.json.JSONObject;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

    @GetMapping("/")
    public String index(){

        return "home";
    }

    @GetMapping("/loginPage")
    public String loginPage(){
        return "로그인 성공페이지";
    }

    @GetMapping("/user")
    public String user(){
        return "user";
    }
    @GetMapping("/admin/pay")
    public String adminPay(){
        return "adminPay";
    }
    @GetMapping("/admin/**")
    public String admin(){
        return "admin";
    }
    @GetMapping("/login")
    public String login(){
        return "login";
    }
    @GetMapping("/denied")
    public String denied(){
        return "Access is denied";
    }
    @GetMapping("/userInfo")
    public String  userInfo(Authentication authentication){
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("id", authentication.getName());
        jsonObject.put("auth", authentication.getAuthorities());
        System.out.println("제이슨 데이터 :"+jsonObject);
        return jsonObject.toString();
    }
}
