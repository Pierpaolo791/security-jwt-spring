package com.dmi.securityJWT.controller;

import com.dmi.securityJWT.model.Account;
import com.dmi.securityJWT.model.AuthenticationRequest;
import com.dmi.securityJWT.model.AuthenticationResponse;
import com.dmi.securityJWT.service.AccountService;
import com.dmi.securityJWT.service.MyUserDetailsService;
import com.dmi.securityJWT.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @Autowired
    private AuthenticationManager authenticationManager;
    
    @Autowired
    private MyUserDetailsService userDetailsService;
    
    @Autowired 
    private AccountService accountService;
    
    @Autowired
    private JwtUtil jwtUtil; 
    
    @Autowired 
    private PasswordEncoder encoder; 

    @RequestMapping("/home")
    public String home(@RequestHeader("Authorization") String token) {
        return "Hello world " + jwtUtil.extractUsername(token.replace("Bearer ", ""));
    }
    
    @RequestMapping("/getMe")
    public @ResponseBody Account getMe(@RequestHeader("Authorization") String token) {
        Account me = accountService.getAccount(jwtUtil.extractUsername(token.replace("Bearer ", "")));
        me.setPassword(null);
        return me;
    }

    @RequestMapping(value = "/auth", method = RequestMethod.POST)
    public ResponseEntity<?> createAuthToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword())
            );
        } catch (BadCredentialsException e) {
            throw new Exception("Incorrent username or password", e);
        }
        final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());
        final String jwt = jwtUtil.generateToken(userDetails);
        return ResponseEntity.ok(new AuthenticationResponse(jwt));
    }
    
    
    @RequestMapping(value = "/register", method = RequestMethod.POST) 
    public ResponseEntity<?> createAuthToken(@RequestBody Account newAccount) {
        
        newAccount.setPassword(encoder.encode(newAccount.getPassword()));
        accountService.saveAccount(newAccount);
        
        return ResponseEntity.ok(newAccount);
    }

    @RequestMapping(value = "/validate", method = RequestMethod.POST) 
    public ResponseEntity validateToken(@RequestHeader("Authorization") String token) {
        return ResponseEntity.ok(true);
        
    }
    
}
