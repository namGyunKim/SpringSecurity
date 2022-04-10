package io.security.basicsecurity;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;


@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
//                인가 정책
                .authorizeRequests()
                .anyRequest().authenticated()  //어떠한 요청에도 다 허락
        ;

//        인증 정책
        http
                .formLogin()    //폼 로그인 방식으로
//                .loginPage("/loginPage")        //사용자 정의 로그인 페이지
//                .defaultSuccessUrl("/")         //로그인 성공 후 이동 페이지
//                .failureUrl("/login")           //로그인 실패 후 이동 페이지
                .usernameParameter("userId")    //파라메터 아이디 설정
                .passwordParameter("passwd")    //파라메터 비밀번호 설정
//                .loginProcessingUrl("login_proc")   //로그인 폼 액션 url
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        log.info("로그인 성공 아이디는 :"+authentication.getName());
                        response.sendRedirect("/loginPage");

                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        log.info("로그인 실패 :"+exception.getMessage());
                        response.sendRedirect("/login");
                    }
                })
                .permitAll()
        ;
//        로그아웃

        http
                .logout()
                .logoutUrl("/logout")
//                .logoutSuccessUrl("/login")
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession httpSession =request.getSession();
                        log.info("세션 무효화");
                        httpSession.invalidate();           //세션 무효화
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        log.info("로그아웃 성공");
                        response.sendRedirect("/login");
                    }
                })
                .deleteCookies("remember-me")           //remember-me라는 쿠키를 삭제

        ;

    }
}
