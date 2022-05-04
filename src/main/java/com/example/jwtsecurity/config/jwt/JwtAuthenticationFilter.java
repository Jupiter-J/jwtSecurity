package com.example.jwtsecurity.config.jwt;

import com.example.jwtsecurity.config.auth.PrincipalDetails;
import com.example.jwtsecurity.model.User;
import com.example.jwtsecurity.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;

/**
 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있다.
 /login 요청해서 username, password 전송(post) 하면
 UsernamePasswordAuthenticationFilter 동작을 한다
 단 이 필터는 formLogin을 통해서 작동을 한다. 현재 시큐리티에서 disable을 했음, 필터추가!
 * */

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;


    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter: 로그인 시도중");

        //1. username, password 받아서
        try{
//            BufferedReader br = request.getReader();
//            String input = null;
//            while((input = br.readLine()) != null){
//                System.out.println(input);
//            }

            //파싱하기
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            //토큰 만들기
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            //PrincipalDetailsService의 loadUserByUsername() 함수가 실행됨
            Authentication authentication =
                    authenticationManager.authenticate(authenticationToken);

            //authentication 객체가 session 영역에 저장됨 => 로그인이 되었다는 뜻
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println(principalDetails.getUser().getUsername());
            System.out.println("1=======================================");
            return authentication;

        }catch (IOException e){
            e.printStackTrace();
        }
        System.out.println("2=======================================");

        //2. 정상인지 로그인 시도 authenticationManager 로 로그인 시도를 하면

        // principalDetailsService 가 호출 loadUserByUsername 실행

        //3. PrincipalDetails 를 세션에 담고 (권한관리를 위해서)

        //4. JWT 토큰을 만들어서 응답해주면 된다
        return null;
    }



}
