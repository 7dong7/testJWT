package org.myjwt.springjwt.service;

import lombok.RequiredArgsConstructor;
import org.myjwt.springjwt.dto.JoinDTO;
import org.myjwt.springjwt.entity.UserEntity;
import org.myjwt.springjwt.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public void joinProcess(JoinDTO joinDTO) {
        String username = joinDTO.getUsername();
        String password = joinDTO.getPassword();

        Boolean isExist = userRepository.existsByUsername(username);

        if (isExist) {
        // 이 메소드의 반환 타입을 void -> Boolean 으로 변경하고 회원가입 여부의 메시지를 사용자에게 전달할 수도 있음
            return;
        }

        UserEntity data = new UserEntity();

        data.setUsername(username);
        data.setPassword(bCryptPasswordEncoder.encode(password));
        data.setRole("ROLE_ADMIN");

        userRepository.save(data);

    }

}
