package com.yxyl.springboot.filter;

import com.yxyl.springboot.model.auth.LoginUser;
import com.yxyl.springboot.utils.JwtUtil;
import com.yxyl.springboot.utils.RedisCache;
import io.jsonwebtoken.Claims;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.annotation.Resource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    private static final String REDIS_KEY = "USER_LOGIN:";
    @Resource
    RedisCache redisCache;


    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        //这里就是重写拦截方法
        try {
            //取出 header 中的 token 进行校验
            String token = request.getHeader("token");
            if (token != null && !"".equals(token)) {
                //解析获取userId
                Claims claims = JwtUtil.parseJWT(token);
                String studentId = claims.getSubject();
                //通过userID获取redis中的缓存信息
                LoginUser loginUser = redisCache.getCacheObject(REDIS_KEY + studentId);
                if (loginUser != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    //token失效了
                    //刷新令牌
                    redisCache.setCacheObject(REDIS_KEY + studentId, loginUser);
                    //从redis中获取loginUse信息放到上下文中
                    UsernamePasswordAuthenticationToken
                            authenticationToken = new UsernamePasswordAuthenticationToken(loginUser.getUser().getId(), loginUser.getPassword());
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }
            }
        } catch (Exception e) {
            filterChain.doFilter(request, response);
            return;
        }
        // 如果token为空直接下一步过滤器，此时上线文中无用户信息，所有在后续认证环节失败
        filterChain.doFilter(request, response);
    }
}