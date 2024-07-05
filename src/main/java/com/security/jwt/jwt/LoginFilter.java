package com.security.jwt.jwt;

import com.security.jwt.dto.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Collection;
import java.util.Iterator;

@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    /**
     * 그니까 스프링 시큐리티를 설정하면 지정 Form에서 가져와서 로그인을 하는데
     * 우리는 form 로그인을 막아뒀으니까
     * 우리가 맞게 검증을 하는 필터를 만드는 과정
     */


    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;


    /**
     * 받아오는 username, password 두가지를 검증해주는 과정
     * @param request
     * @param response
     * @return
     * @throws ArithmeticException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
    throws ArithmeticException {

        String username = obtainUsername(request);
        String password = obtainPassword(request);

        System.out.println("username = " + username);

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username,password, null);

        return authenticationManager.authenticate(authToken);
    }


    //로그인 성공시 실행하는 메소드 (여기서 JWT를 발급하면 됨)
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {

        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();

        String username = customUserDetails.getUsername();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();

        String role = auth.getAuthority();


        String token = jwtUtil.createJwt(username, role, 60*60*10L);

        response.addHeader("Authorization", "Bearer "+token);
    }

    //로그인 실패시 실행하는 메소드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
        response.setStatus(401);
    }


}
