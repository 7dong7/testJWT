package org.myjwt.springjwt.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.myjwt.springjwt.dto.CustomUserDetails;
import org.myjwt.springjwt.entity.UserEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.PrintWriter;

@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    // 인가 작업 // header 의 토큰에서 권한을 확인하는 필터
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // ==== 단일 토큰 ==== //
//        // request 에서 Authorization 헤더를 찾음
//        String authorization = request.getHeader("Authorization");
//
//        if (authorization == null || !authorization.startsWith("Bearer ")) { // 내가 원하는게 아닌 경우
//            System.out.println("=== token null ===");
//            filterChain.doFilter(request, response); // 다음 필터에 넘겨주기
//            return;
//        }
//
//        System.out.println("=== Authorization ===");
//        String token = authorization.split(" ")[1];
//
//        if (jwtUtil.isExpired(token)) { // 토큰 만료
//            System.out.println("=== token expired ===");
//            filterChain.doFilter(request, response);
//            return;
//        }
//
//        String username = jwtUtil.getUsername(token);
//        String role = jwtUtil.getRole(token);
//
//        UserEntity userEntity = new UserEntity();
//        userEntity.setUsername(username);
//        userEntity.setPassword("temppassword"); // 임시 비밀번호
//        userEntity.setRole(role);
//
//        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);
//
//        // 스프링 인증 토큰 생성
//        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
//
//        // 세션에 사용자 등록
//        SecurityContextHolder.getContext().setAuthentication(authToken);
//
//        filterChain.doFilter(request, response);


        // ==== 다중 토큰 ==== //
        // 헤더에서 access 키에 담긴 토큰을 꺼냄
        String accessToken = request.getHeader("access");

        // 토큰이 없다면 다음 필터로 넘김
        if (accessToken == null) {

            filterChain.doFilter(request, response);

            return;
        }

        // 토큰 만료 여부 확인, 만료시 다음 필터로 넘기지 않음
        try {
            jwtUtil.isExpired(accessToken);
        } catch (ExpiredJwtException e) {

            //response body
            PrintWriter writer = response.getWriter();
            writer.print("access token expired");

            //response status code
                /*
                * 이런 상태코드를 프론트 쪽으로 보내고, 프론트 쪽에서 이 상태코드를 받아서
                * access 토큰이 만료되었으니까 Refresh 토큰을 사용해서 access 토큰을 재발급 받는 경로로 이동하도록 한다
                * 따라서, 프론트와의 이 상태코드에 대한 약속을 해두어야 한다
                * */
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); 
            return;
        }

        // 만료가 되지 않은 토큰인 경우 Access 토크인지 Refresh 토큰인지 확인
        // 토큰이 access 인지 확인 (발급시 페이로드에 명시)
        String category = jwtUtil.getCategory(accessToken);

        if (!category.equals("access")) {

            //response body
            PrintWriter writer = response.getWriter();
            writer.print("invalid access token");

            //response status code
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        // username, role 값을 획득
        String username = jwtUtil.getUsername(accessToken);
        String role = jwtUtil.getRole(accessToken);

        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setRole(role);
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
        // 여기에 등록시키면 일시적으로 세션이 만들어진다. 로그인된 상태로 변경
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}
