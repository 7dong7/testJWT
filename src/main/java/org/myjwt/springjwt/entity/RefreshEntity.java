package org.myjwt.springjwt.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Data;

@Entity
@Data
public class RefreshEntity {
    
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username; // 하나의 유저에 대해서 여러 개의 토큰을 가지고 있을 수 있으므로 unique 설정을 하면 안됨
    private String refresh;
    private String expiration;
}
