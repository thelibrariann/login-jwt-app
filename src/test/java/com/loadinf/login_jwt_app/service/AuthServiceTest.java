package com.loadinf.login_jwt_app.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.loadinf.login_jwt_app.dto.AuthResponse;
import com.loadinf.login_jwt_app.dto.LoginRequest;
import com.loadinf.login_jwt_app.dto.RegisterRequest;
import com.loadinf.login_jwt_app.entity.Role;
import com.loadinf.login_jwt_app.entity.User;
import com.loadinf.login_jwt_app.repository.UserRepository;
import com.loadinf.login_jwt_app.security.JwtService;

import java.util.Optional;

/**
 * Tests unitarios para AuthService
 *
 * @ExtendWith(MockitoExtension.class) - Habilita Mockito para JUnit 5
 * @Mock - Crea objetos mock (simulados) de las dependencias
 * @InjectMocks - Crea una instancia de AuthService e inyecta los mocks
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AuthService Tests")
class AuthServiceTest {

    // Mocks de las dependencias
    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @Mock
    private AuthenticationManager authenticationManager;

    // Clase a testear con mocks inyectados
    @InjectMocks
    private AuthService authService;

    // Variables para reutilizar en los tests
    private RegisterRequest registerRequest;
    private LoginRequest loginRequest;
    private User user;

    /**
     * @BeforeEach se ejecuta ANTES de cada test
     * Aquí preparamos los datos de prueba
     */
    @BeforeEach
    void setUp() {
        // Preparar datos de prueba
        registerRequest = RegisterRequest.builder()
            .username("testuser")
            .email("test@example.com")
            .password("password123")
            .build();

        loginRequest = LoginRequest.builder()
            .username("testuser")
            .password("password123")
            .build();

        user = User.builder()
            .id(1L)
            .username("testuser")
            .email("test@example.com")
            .password("hashedPassword")
            .role(Role.ROLE_USER)
            .build();
    }

    /**
     * TEST 1: Registro exitoso
     *
     * Pasos:
     * 1. Configurar el comportamiento de los mocks con when().thenReturn()
     * 2. Ejecutar el método a testear
     * 3. Verificar el resultado con assertions
     * 4. Verificar que se llamaron los métodos esperados con verify()
     */
    @Test
    @DisplayName("Should register user successfully")
    void testRegister_Success() {
        // ARRANGE (Preparar)
        // Simular que username y email NO existen
        when(userRepository.existsByUsername("testuser")).thenReturn(false);
        when(userRepository.existsByEmail("test@example.com")).thenReturn(false);

        // Simular el encoding de password
        when(passwordEncoder.encode("password123")).thenReturn("hashedPassword");

        // Simular el guardado del usuario
        when(userRepository.save(any(User.class))).thenReturn(user);

        // Simular la generación del token
        when(jwtService.generateToken(any(User.class))).thenReturn("fake-jwt-token");

        // ACT (Actuar) - Ejecutar el método
        AuthResponse response = authService.register(registerRequest);

        // ASSERT (Afirmar) - Verificar resultados
        assertNotNull(response);
        assertEquals("fake-jwt-token", response.getToken());
        assertEquals("testuser", response.getUsername());
        assertEquals("test@example.com", response.getEmail());
        assertEquals("ROLE_USER", response.getRole());

        // VERIFY (Verificar) - Comprobar que se llamaron los métodos
        verify(userRepository, times(1)).existsByUsername("testuser");
        verify(userRepository, times(1)).existsByEmail("test@example.com");
        verify(passwordEncoder, times(1)).encode("password123");
        verify(userRepository, times(1)).save(any(User.class));
        verify(jwtService, times(1)).generateToken(any(User.class));
    }

    /**
     * TEST 2: Registro falla - Username ya existe
     *
     * Usamos assertThrows para verificar que se lanza una excepción
     */
    @Test
    @DisplayName("Should throw exception when username already exists")
    void testRegister_UsernameExists() {
        // ARRANGE
        when(userRepository.existsByUsername("testuser")).thenReturn(true);

        // ACT & ASSERT
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            authService.register(registerRequest);
        });

        assertEquals("Username is already taken", exception.getMessage());

        // VERIFY - No debería llamarse save() porque lanzó excepción antes
        verify(userRepository, never()).save(any(User.class));
    }

    /**
     * TEST 3: Registro falla - Email ya existe
     */
    @Test
    @DisplayName("Should throw exception when email already exists")
    void testRegister_EmailExists() {
        // ARRANGE
        when(userRepository.existsByUsername("testuser")).thenReturn(false);
        when(userRepository.existsByEmail("test@example.com")).thenReturn(true);

        // ACT & ASSERT
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            authService.register(registerRequest);
        });

        assertEquals("Email is already in use", exception.getMessage());
        verify(userRepository, never()).save(any(User.class));
    }

    /**
     * TEST 4: Login exitoso
     */
    @Test
    @DisplayName("Should login user successfully")
    void testLogin_Success() {
        // ARRANGE
        // Simular autenticación exitosa (no lanza excepción)
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
            .thenReturn(null); // El método no retorna nada importante, solo valida

        // Simular que el usuario existe
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));

        // Simular generación de token
        when(jwtService.generateToken(user)).thenReturn("login-jwt-token");

        // ACT
        AuthResponse response = authService.login(loginRequest);

        // ASSERT
        assertNotNull(response);
        assertEquals("login-jwt-token", response.getToken());
        assertEquals("testuser", response.getUsername());
        assertEquals("test@example.com", response.getEmail());
        assertEquals("ROLE_USER", response.getRole());

        // VERIFY
        verify(authenticationManager, times(1)).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(userRepository, times(1)).findByUsername("testuser");
        verify(jwtService, times(1)).generateToken(user);
    }

    /**
     * TEST 5: Login falla - Usuario no encontrado
     */
    @Test
    @DisplayName("Should throw exception when user not found during login")
    void testLogin_UserNotFound() {
        // ARRANGE
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
            .thenReturn(null);
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.empty());

        // ACT & ASSERT
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            authService.login(loginRequest);
        });

        assertEquals("User not found", exception.getMessage());
    }
}
