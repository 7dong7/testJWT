package org.myjwt.springjwt.repository;

import org.myjwt.springjwt.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Integer> {

    // 사용자 중복 여부 By username
    Boolean existsByUsername(String username);

    // 사용자 조회
    UserEntity findByUsername(String username);
}
