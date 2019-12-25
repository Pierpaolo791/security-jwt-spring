package com.dmi.securityJWT.service;

import com.dmi.securityJWT.model.Account;
import com.dmi.securityJWT.repository.AccountRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AccountService {
    
    @Autowired
    private AccountRepository repository;
    
    public Account getAccount(String username) {
        return repository.findByUsername(username);
    }
    
    public void saveAccount(Account account) {
        repository.save(account);
    }
}
