package com.oauth.authorization.domain;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

@Getter @Setter
@NoArgsConstructor
public class Account implements UserDetails {

    private Long id;
    private String name;
    private String email;
    private String password;
    private String mobile;
    private String gender;

    private String roles;


    @Builder
    public Account(
            Long id,
            String name,
            String email,
            String password,
            String mobile,
            String gender,
            String role
    ){
        this.id = id;
        this.name = name;
        this.email = email;
        this.password = password;
        this.mobile = mobile;
        this.gender = gender;
        this.roles = role;
    }


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if(this.roles == null) return Collections.singleton(new SimpleGrantedAuthority(null));
        return Collections.singleton(new SimpleGrantedAuthority(this.roles));
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
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
