package com.svet.authservice.controllers;

import com.svet.authservice.dto.JwtDto;
import com.svet.authservice.dto.RefreshTokenDto;
import com.svet.authservice.dto.UserCredentials;
import com.svet.authservice.dto.UserDto;
import com.svet.authservice.handlers.ErrorHandler;
import com.svet.authservice.services.MyUserDetails;
import com.svet.authservice.services.UserServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.naming.AuthenticationException;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserServiceImpl userService;

    @PostMapping("/signIn")
    public ResponseEntity<?> signIn(@RequestBody UserCredentials userCredentials) {
        try {
            JwtDto jwtDto = userService.signIn(userCredentials);
            return ResponseEntity.ok(jwtDto);
        } catch (AuthenticationException e) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/register")
    public ResponseEntity<?> createUser(@RequestBody UserDto userDto) throws Exception {
        try {
            UserDto createdUser = userService.createUser(userDto);
            return ResponseEntity.status(HttpStatus.CREATED).body(createdUser);
        } catch (ErrorHandler.UserAlreadyExistsException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Map.of("error", e.getMessage()));
        } catch (ErrorHandler.UserCreationException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Internal server error"));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<JwtDto> refreshToken(@RequestBody RefreshTokenDto refreshTokenDto) throws Exception {
        JwtDto jwt =  userService.refreshToken(refreshTokenDto);
        return ResponseEntity.ok(jwt);
    }

    @PostMapping("/protected")
    public String protectedRoute() {
        return "protected";
    }
}