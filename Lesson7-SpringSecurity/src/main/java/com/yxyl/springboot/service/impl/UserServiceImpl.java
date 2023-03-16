package com.yxyl.springboot.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.yxyl.springboot.mapper.UserMapper;
import com.yxyl.springboot.model.User;
import com.yxyl.springboot.model.auth.LoginUser;
import com.yxyl.springboot.model.auth.UserResponse;
import com.yxyl.springboot.service.UserService;
import com.yxyl.springboot.utils.JwtUtil;
import com.yxyl.springboot.utils.RedisCache;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@AllArgsConstructor
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements UserService {

    public final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final RedisCache redisCache;

    private static final String REDIS_KEY = "USER_LOGIN:";


    @Override
    public List<User> listAll() {
        return list();
    }

    @Override
    public UserResponse login(User user) {
        UsernamePasswordAuthenticationToken
                authenticationToken = new UsernamePasswordAuthenticationToken(user.getId(), user.getPassword());
        Authentication authenticate = authenticationManager.authenticate(authenticationToken);
        LoginUser loginUser = (LoginUser) authenticate.getPrincipal();
        //能到这里，说明数据库中是有这个用户的,但是还得判断password是否匹配
        if (!passwordEncoder.matches(user.getPassword(),loginUser.getPassword())) {
            //如果密码不匹配
            throw new RuntimeException("密码错误");
        }
        
        //获取userId
        String userId = loginUser.getUser().getId().toString();
        String token = JwtUtil.createJWT(userId);
        //TODO 这里还可以吧loginUser信息放在Redis里面，方便以后的功能模块会用到
        redisCache.setCacheObject(REDIS_KEY + userId, loginUser);
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        
        return new UserResponse(token, loginUser.getUser());
    }

    @Override
    public User regis(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        save(user);
        return user;
    }
}
