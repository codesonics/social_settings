package com.example.social.user;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserRegisterService {
    private final UserFindService userFindService;
    private final UserRepository userRepository;

    public void requireRegistration(final String name, final String email){
        final boolean exits = userFindService.exitsByEmail(email);
        if(!exits){
            final User user = new User(name, email);
            userRepository.save(user);
        }
    }


}
