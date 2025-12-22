package com.svet.authservice.services;

import com.svet.authservice.dto.JwtDto;
import com.svet.authservice.dto.RefreshTokenDto;
import com.svet.authservice.dto.UserCredentials;
import com.svet.authservice.dto.UserDto;
import com.svet.authservice.entities.User;
import com.svet.authservice.enums.ERole;
import com.svet.authservice.handlers.ErrorHandler;
import com.svet.authservice.repositories.RoleRepo;
import com.svet.authservice.repositories.UserRepo;
import com.svet.authservice.security.jwt.JwtService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.data.crossstore.ChangeSetPersister;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.naming.AuthenticationException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepo userRepo;
    private final RoleRepo roleRepo;
    private final PasswordEncoder encoder;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public JwtDto signIn(UserCredentials userCredentials) throws AuthenticationException {
        User user = findByCredentials(userCredentials);
        Map<String, Object> claims = setUserClaims(user);
        return jwtService.generateTokens(claims, user.getUsername());
    }

    @Override
    public JwtDto refreshToken(RefreshTokenDto refreshTokenDto) throws Exception {
        String token = refreshTokenDto.getToken();
        if (token != null && jwtService.validateToken(token)) {
            User user = findBySubject(token);
            Map<String, Object> claims = setUserClaims(user);
            return jwtService.generateTokens(claims, user.getUsername());
        }
        return null;
    }

    @Override
    @Transactional
    public UserDto createUser(UserDto userDto) throws Exception {

        if (userRepo.existsByEmail(userDto.getEmail())) {
            throw new ErrorHandler.UserAlreadyExistsException("User with email " + userDto.getEmail() + " already exists");
        }

        if (userRepo.existsByUsername(userDto.getUsername())) {
            throw new ErrorHandler.UserAlreadyExistsException("User with username " + userDto.getUsername() + " already exists");
        }
        User user = new User();
        user.setEmail(userDto.getEmail());
        user.setPassword(encoder.encode(userDto.getPassword()));
        user.setUsername(userDto.getUsername());
        user.setRoles(List.of(roleRepo.findByName(ERole.ROLE_USER)
                .orElseThrow(() -> new RuntimeException("Error: Role is not found."))));

        try {
            User savedUser = userRepo.save(user);
            return convertUserToUserDto(savedUser);
        } catch (Exception e) {
            throw new ErrorHandler.UserCreationException("Failed to create user: " + e.getMessage());
        }
    }

    @Override
    @Transactional
    public UserDto getUserById(Long id) throws ChangeSetPersister.NotFoundException {
        User user = userRepo.findById(id)
                .orElseThrow(ChangeSetPersister.NotFoundException::new);
        return convertUserToUserDto(user);
    }

    @Override
    @Transactional
    public UserDto getUserByUsername(String username) throws ChangeSetPersister.NotFoundException {
        User user = userRepo.findByUsername(username)
                .orElseThrow(ChangeSetPersister.NotFoundException::new);
        return convertUserToUserDto(user);
    }

    private User findBySubject(String token) throws ChangeSetPersister.NotFoundException  {
        User user = userRepo.findByUsername(jwtService.extractUsername(token))
                .orElseThrow(ChangeSetPersister.NotFoundException::new);
        return user;
    }

    private User findByCredentials(UserCredentials userCredentials) throws AuthenticationException {
        Optional<User> user = userRepo.findByUsername(userCredentials.getUsername());

        if (user.isEmpty()) throw new AuthenticationException("User wasn't found");

        User foundUser = user.get();

        if (!passwordEncoder.matches(userCredentials.getPassword(), foundUser.getPassword())) {
            throw new AuthenticationException("Wrong password");
        }

        return foundUser;
    }

    private Map<String, Object> setUserClaims(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("id", user.getId());
//        claims.put("roles", user.getRoles());
        return claims;
    }

    private UserDto convertUserToUserDto(User user) {
        UserDto userDto = new UserDto();
        userDto.setId(user.getId());
        userDto.setEmail(user.getEmail());
        userDto.setUsername(user.getUsername());
        userDto.setPassword(user.getPassword());
//        userDto.setRoles(user.getRoles());
        return userDto;
    }
}
