package com.loadinf.login_jwt_app.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.loadinf.login_jwt_app.dto.AuthResponse;
import com.loadinf.login_jwt_app.dto.LoginRequest;
import com.loadinf.login_jwt_app.dto.RegisterRequest;
import com.loadinf.login_jwt_app.entity.Role;
import com.loadinf.login_jwt_app.entity.User;
import com.loadinf.login_jwt_app.repository.UserRepository;
import com.loadinf.login_jwt_app.security.JwtService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthResponse register(RegisterRequest request) {

        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Username is already taken");
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email is already in use");
        }

        var user = User.builder()
            .username(request.getUsername())
            .email(request.getEmail())
            .password(passwordEncoder.encode(request.getPassword()))
            .role(Role.ROLE_USER)
            .build();
        
        userRepository.save(user);

        var jwtToken = jwtService.generateToken(user);

        return AuthResponse.builder()
            .token(jwtToken)
            .username(user.getUsername())
            .email(user.getEmail())
            .role(user.getRole().name())
            .build();
    }

    public AuthResponse login(LoginRequest request) {
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                request.getUsername(),
                request.getPassword()
            )
        );

        var user = userRepository.findByUsername(request.getUsername())
            .orElseThrow(() -> new RuntimeException("User not found"));

        var jwtToken = jwtService.generateToken(user);

        return AuthResponse.builder()
            .token(jwtToken)
            .username(user.getUsername())
            .email(user.getEmail())
            .role(user.getRole().name())
            .build();
    }
}
