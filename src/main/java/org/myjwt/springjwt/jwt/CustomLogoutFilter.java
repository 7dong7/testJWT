package org.myjwt.springjwt.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.myjwt.springjwt.repository.RefreshRepository;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

@RequiredArgsConstructor
public class CustomLogoutFilter extends GenericFilterBean {

    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }

    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {

        // 로그아웃 요청이 들어왔을 때
        // 경로 확인
        String requestUri = request.getRequestURI();
        if(!requestUri.matches("^\\/logout$")) {
            filterChain.doFilter(request, response);
            return;
        }
        // post 확인
        String requestMethod = request.getMethod();
        if (!requestMethod.equals("POST")) {
            filterChain.doFilter(request, response);
            return;
        }
        
        // refresh 토큰 확인
        String refresh = null;
        Cookie[] cookies = request.getCookies(); // 쿠키들을 불러온다
        for (Cookie cookie : cookies) {

            if(cookie.getName().equals("refresh")) { // 쿠키들중에 refresh 토큰이 있는지 확인
                refresh = cookie.getValue();
            }
        }
        
        // refresh null 체크
        if (refresh == null) { // refresh 토큰이 없는 경우

            response.setStatus(HttpServletResponse.SC_BAD_REQUEST); // response status code
            return;
        }

        // 만료 확인
        try {
            jwtUtil.isExpired(refresh);
        } catch (ExpiredJwtException e) {

            //response status code
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // 토큰이 refresh 인지 확인 (발급시 페이로드에 명시)
        String category = jwtUtil.getCategory(refresh);
        if (!category.equals("refresh")) {

            //response status code
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        //DB에 저장되어 있는지 확인
        Boolean isExist = refreshRepository.existsByRefresh(refresh);
        if (!isExist) {

            //response status code
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        //로그아웃 진행
        //Refresh 토큰 DB에서 제거
        refreshRepository.deleteByRefresh(refresh);

        //Refresh 토큰 Cookie 값 0
        Cookie cookie = new Cookie("refresh", null); // 쿠키 삭제
        cookie.setMaxAge(0); // 쿠키 시간 0
        cookie.setPath("/"); // 쿠키 경로

        response.addCookie(cookie); // 쿠키 추가 (초기화 쿠키)
        response.setStatus(HttpServletResponse.SC_OK);
    }

}
