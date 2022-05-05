package com.example.jwtsecurity.config.auth;


import com.example.jwtsecurity.model.User;
import com.example.jwtsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

//http://localhost:8080/login 동작을 할때 실행
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    private final Logger logger = LoggerFactory.getLogger(PrincipalDetailsService.class);

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        logger.info("PrincipalDetailsService 의 loadUserByUsername() 진입~~ ");

        User userEntity = userRepository.findByUsername(username);
        logger.info("userEntity: {}", userEntity);
        return new PrincipalDetails(userEntity);
    }


}
