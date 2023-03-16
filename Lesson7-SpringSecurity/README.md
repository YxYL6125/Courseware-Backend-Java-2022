# 2023春季蓝山工作室第一次课

## Spring Security

Spring Security是一个功能强大且高度可定制的身份验证和访问控制框架。它是保护基于spring的应用程序的事实上的标准。

Spring Security是一个专注于为Java应用程序提供身份验证和授权的框架。像所有Spring项目一样，Spring Security的真正力量在于它可以很容易地扩展以满足定制需求

### 开始工作

> 1. ```java
>    <dependency>
>        <groupId>org.springframework.boot</groupId>
>        <artifactId>spring-boot-starter-security</artifactId>
>    </dependency>
>    ```
>
> 2. 开写……

在导完依赖过后，我们直接写一个简单的hello接口

注意：这里请导 springboot 3.0 以下版本的依赖

![image-20230314184002953](/home/yxyl/.config/Typora/typora-user-images/image-20230314184002953.png)

然后我们启动项目，并且访问这个接口：`localhost:8080/hello`

本来应该出现hello字符串返回的，但是页面却出现了让我们的登陆的界面：

![image-20230314184311328](/home/yxyl/.config/Typora/typora-user-images/image-20230314184311328.png)

这生活你就回想：

> 我￥%……&*（——，我自己从创建项目到遇见你，什么时候设置或者见过username,password啊

诶～，别急，细心的你已经发现了，在控制台已经输出了我们想要的password：

![image-20230314184534140](/home/yxyl/.config/Typora/typora-user-images/image-20230314184534140.png)

然后username：user

如果我们不设置账号密码的话，Spring Security 默认就会给我们配置账号密码

在输入username,password过后，我们就可以看到想看到的hello了

![image-20230314184734793](/home/yxyl/.config/Typora/typora-user-images/image-20230314184734793.png)

当然，如果你想自己设置密码的话：

```yml
server:
  port: 8080
spring:
  security:
    user:
      password: 6125
```

综上：在不配置任何信息的情况下，Spring Security 会为我们拦截所有的资源访问，但是这与我们开发的需求相比还远远不够……



### 配置Sucurity

在开发过程中，我们总有一些接口是不能直接对外暴漏出去的，其调用者必须拥有某些权限，才能获取相关接口资源，所以，我们通过自定义SecurityConfig配置类，去继承`WebSecurityConfigurerAdapter`，重写`protected void configure(HttpSecurity http)`方法，来配置我们自己的授权认证规则





这个是最开始的配置类：

```java
package com.yxyl.springboot.config;

import org.apache.catalina.filters.AddDefaultCharsetFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .cors()//允许跨域
                .and()
                .csrf().disable()//关闭csrf
                .authorizeRequests()
//                .antMatchers("/").anonymous()
                .antMatchers("/user").permitAll()
                .anyRequest().authenticated();
        
        http.formLogin().permitAll();
    }

    @Bean//这个东西等下可由大用处
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
```

这里我们设置了：

> 1. `/user`这个接口，任何人都是可以访问的
> 2. 除了`/user`接口之外，其他的接口(/hello)必须需要认证授权才能访问

到这里你会想，我不可能在访问需要授权的资源的时候，每次都要经过这样一个很丑，很丑，很丑的界面吧，所以，我们吧登陆界面这样的事情交给前殿



### 完成我们的登陆功能

接下来就可以完成我们的登陆功能了

先创建一个User类和UserRespnse：

```java
package com.yxyl.springboot.model;

import com.baomidou.mybatisplus.annotation.TableName;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.io.Serializable;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
@TableName("user")

public class User implements Serializable {
    private Long id;
    private String username;
    private String password;
    private String role;
}
==============================================================================================================
package com.yxyl.springboot.model.auth;

import com.yxyl.springboot.model.User;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class UserResponse {
    private String token;
    private User user;
}
```

我们在UserController里面编写一个Post请求的login接口

```java
    @PostMapping("/login")
    public UserResponse login(@RequestBody User user) {
        if (user == null) {
            throw new RuntimeException("user can not be null");
        }
        return userService.login(user);
    }
```

UserServiceIml：

```java
public final UserMapper userMapper;
private final PasswordEncoder passwordEncoder;
private final AuthenticationManager authenticationManager;
private final RedisCache redisCache;

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
```

我们首先进行一个“授权管理者的验证”过程

这个`AuthenticationManager`就是我们在SecurityConfig里面注入进去的，用于登陆前的验证
`authenticationManager.authenticate()`方法就是验证方法

这里需要我们实现`UserDetailsService`接口，重写`loadUserByUsername(String str)`方法

代码如下：

```java
package com.yxyl.springboot.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.yxyl.springboot.mapper.UserMapper;
import com.yxyl.springboot.model.User;
import com.yxyl.springboot.model.auth.LoginUser;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class UserDetailServiceImpl implements UserDetailsService {
    private final UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String id) throws UsernameNotFoundException {
        //在“认证授权管理器的认证”方法之前，先判断是否有这个用户
        User user = userMapper.selectOne(new LambdaQueryWrapper<User>().eq(User::getId, id));
        if (user == null) {
            throw new UsernameNotFoundException("用户不存在");
        }
        //TODO 用户权限(Role)封装

        return new LoginUser(user);
    }
}
```

通过代码我们可以看到，这个所谓的“登陆前校验”无非就是验证传进来User的studentId是否在数据库中存在，如果不存在就直接报错返回，不再进行后续的登陆逻辑（比如密码是否正确之类的）了;如果存在的话，就将其封装成`LoginUser`返回

LoginUser 实现 UserDetails接口：UserDetails是Security中为我们提供的可实现的**认证用户的接口**

```java
package com.yxyl.springboot.model.auth;

import com.yxyl.springboot.model.User;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class LoginUser implements UserDetails {

    private User user;


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
```



OK到这里，我们的登陆功能就写完力(ง •̀_•́)ง

我们来测试一下吧：

![image-20230316110831099](/home/yxyl/.config/Typora/typora-user-images/image-20230316110831099.png)

可以看到，返回来我们封装的UserResponse





