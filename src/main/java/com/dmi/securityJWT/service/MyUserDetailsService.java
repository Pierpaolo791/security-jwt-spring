package com.dmi.securityJWT.service;

import com.dmi.securityJWT.model.Account;
import java.util.ArrayList;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetailsService implements UserDetailsService{
    
    @Autowired
    private AccountService accountService;
    
    @Override
    public UserDetails loadUserByUsername(String string) throws UsernameNotFoundException {
        Account account = accountService.getAccount(string);
        return new User(account.getUsername(),account.getPassword(), new ArrayList<>()); 
    }
    
    
    
}
