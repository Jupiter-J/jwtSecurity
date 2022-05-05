package com.example.jwtsecurity.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwtsecurity.config.auth.PrincipalDetails;
import com.example.jwtsecurity.dto.LoginRequestDto;
import com.example.jwtsecurity.model.User;
import com.example.jwtsecurity.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

/**
 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있다.
 /login 요청해서 username, password 전송(post) 하면
 UsernamePasswordAuthenticationFilter 동작을 한다
 단 이 필터는 formLogin을 통해서 작동을 한다. 현재 시큐리티에서 disable을 했음, 필터추가!
 * */

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);


    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        logger.info("JwtAuthenticationFilter: 진입!! ");

        //파싱하기
        ObjectMapper om = new ObjectMapper();
        LoginRequestDto loginRequestDto = null;

        //1. username, password 받아서
        try{
//            BufferedReader br = request.getReader();
//            String input = null;
//            while((input = br.readLine()) != null){
//                System.out.println(input);
//            }

            loginRequestDto = om.readValue(request.getInputStream(), LoginRequestDto.class);
            logger.info("DB에 들어온값 확인{}",loginRequestDto);

        }catch (Exception e){
            e.printStackTrace();
        }
             logger.info("JWTAuthenticationFilter{}",loginRequestDto);
            //토큰 만들기
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(
                            loginRequestDto.getUsername(),
                            loginRequestDto.getPassword());
        logger.info("JwtAuthenticationFilter : 토큰생성완료");

            //PrincipalDetailsService 의 loadUserByUsername() 함수가 실행된 후 정상이면 authentication 이 리턴됨
            //DB에 있는 username과 password가 일치한다
            Authentication authentication =
                    authenticationManager.authenticate(authenticationToken);

            //=> 로그인이 되었다는 뜻
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            logger.info("login username: {}",principalDetails.getUser().getUsername()); //로그인 정상으로 되었다는 뜻
            /**
             authentication 객체가 session영역에 저장을 해야하고 그 방법이 return이다
             리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 사용!
             굳이 JWT토큰을 사용하면서 세션을 만들 이유가 없다. 단지 권한 처리 때문에 session을 넣어 준다
             * */
            return authentication;



        //2. 정상인지 로그인 시도 authenticationManager 로 로그인 시도를 하면
            // principalDetailsService 가 호출 loadUserByUsername 실행
        //3. PrincipalDetails 를 세션에 담고 (권한관리를 위해서)
        //4. JWT 토큰을 만들어서 응답해주면 된다

    }

    //attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행
    //JWT 토큰을 만들어서 request요청한 사용자에게 JWT토큰을 Response해주면 된다
    @Override
    protected void successfulAuthentication
            (HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult)
            throws IOException, ServletException {
        logger.info("successfulAuthentication 실행: 인증이 완료되었다");

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        //RSA방식이 아닌 Hash암호 방식
        String jwtToken = JWT.create()
                .withSubject(principalDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME)) //토큰유효시간 20분
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));

                            //헤더에 담겨서 사용자에게 응답
        response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX+jwtToken);

    }

}
