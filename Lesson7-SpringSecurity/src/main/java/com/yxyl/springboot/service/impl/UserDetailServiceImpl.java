package com.yxyl.springboot.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.yxyl.springboot.mapper.UserMapper;
import com.yxyl.springboot.model.User;
import com.yxyl.springboot.model.auth.LoginUser;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class UserDetailServiceImpl implements UserDetailsService {
    private final UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String id)  {
        //在“认证授权管理器的认证”方法之前，先判断是否有这个用户
        User user = userMapper.selectOne(new LambdaQueryWrapper<User>().eq(User::getId, id));
        //TODO 用户权限(Role)封装
        
        if (user == null) {
            System.out.printf("用户不存在");
            throw new UsernameNotFoundException("用户不存在");
        }else {
            return new LoginUser(user);
        }
    }
}
