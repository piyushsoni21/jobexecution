package com.jobexecution.service.impl;

import com.jobexecution.service.AuthenticationService;
import com.jobexecution.service.exception.BadRequestException;
import com.jobexecution.service.exception.JobExecutionException;
import com.jobexecution.service.security.JwtService;
import com.jobexecution.service.ws.*;
import com.persistence.model.auth.ConfirmationToken;
import com.persistence.model.auth.RefreshToken;
import com.persistence.model.auth.TokenType;
import com.persistence.model.auth.User;
import com.persistence.repository.auth.ConfirmationTokenRepository;
import com.persistence.repository.auth.RefreshTokenRepository;
import com.persistence.repository.auth.UserRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Date;
import java.util.List;
import java.util.UUID;

import static com.jobexecution.service.util.Constant.*;

@Service
@RequiredArgsConstructor
@Log4j2
public class AuthenticationServiceImpl implements AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TwoFactorAuthenticationServiceImpl tfaService;
    private final ConfirmationTokenRepository confirmationTokenRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenRepository tokenRepository;

    private static final long CONFIRMATION_TOKEN_EXPIRY_TIME = 30 * 60 * 1000; // 30 minutes in milliseconds
    private static final Integer JWT_COOKIE_EXPIRY_TIME = 30 * 60; // 30 minutes
    private static final Integer REFRESH_TOKEN_COOKIE_EXPIRY_TIME = 30 * 60;
    private static final int SESSION_EXPIRY_TIME = 180; // 3 minutes

    @Value("${app.frontend.email-confirm-base-url}")
    private String baseUrl;

    @Override
    @Transactional
    public RegistrationResponseWs register(RegisterRequestWs registerRequest) {
        try {
            log.info("Registration request received for email {}", registerRequest.getEmail());

            userRepository.findByEmail(registerRequest.getEmail())
                    .ifPresent(user -> {
                        throw new BadRequestException("Email already exists");
                    });

            User user = User.builder()
                    .firstName(registerRequest.getFirstName())
                    .lastName(registerRequest.getLastName())
                    .email(registerRequest.getEmail())
                    .password(passwordEncoder.encode(registerRequest.getPassword()))
                    .role(registerRequest.getRole())
                    .mfaEnabled(registerRequest.isMfaEnabled())
                    .build();

            if (registerRequest.isMfaEnabled()){
                user.setSecret(tfaService.generateNewSecret());
            }
            User savedUser = userRepository.save(user);
            ConfirmationToken confirmationToken = ConfirmationToken.builder()
                    .dateCreated(new Date())
                    .user(savedUser)
                    .token(UUID.randomUUID().toString())
                    .build();

            confirmationTokenRepository.save(confirmationToken);
            //emailService.sendUserEmailConfirmation(generateLink(confirmationToken.getToken()),savedUser.getEmail());
            System.out.println(generateLink(confirmationToken.getToken()));
            return RegistrationResponseWs.builder()
                    .message(SUCCESS_RESULT)
                    .name(savedUser.getFirstName().concat(" ").concat(savedUser.getLastName()))
                    .build();
        }
        catch (BadRequestException e){
            throw e;
        }
        catch(Exception e) {
            throw new JobExecutionException("An unexpected error occurred during registration");
        }
    }

    @Override
    public AuthenticationResponseWs login(LoginRequestWs loginRequest, HttpServletRequest request, HttpServletResponse response) {
        try {
            log.info("Login request received for user {}", loginRequest.getEmail());
            userRepository.findByEmail(loginRequest.getEmail()).orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + loginRequest.getEmail()));
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getEmail(),
                            loginRequest.getPassword()
                    )
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);
            User user = (User) authentication.getPrincipal();
            HttpSession session = request.getSession(true);
            session.setAttribute(SPRING_SECURITY_CONTEXT, SecurityContextHolder.getContext());
            session.setMaxInactiveInterval(SESSION_EXPIRY_TIME);

            if (user.isMfaEnabled()){
                return AuthenticationResponseWs.builder()
                        .mfaEnabled(true)
                        .build();
            }
            String token = jwtService.generateToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);
            revokeAllUserToken(user);
            saveUserToken(user, refreshToken);
            setCookies(token,refreshToken,request,response);
            return AuthenticationResponseWs.builder()
                    .name(user.getFirstName().concat(" ").concat(user.getLastName()))
                    .mfaEnabled(false)
                    .build();
        }
        catch (AuthenticationException e){
            if (e instanceof BadCredentialsException) {
                throw new AuthenticationCredentialsNotFoundException("Invalid password", e);
            } else {
                throw e;
            }
        }
        catch (Exception e) {
            throw new JobExecutionException("An unexpected error occurred during login. Please try again later! ", e);
        }
    }

    @Override
    public EmailVerificationTokenResponseWs confirmEmail(String confirmationToken) {
        ConfirmationToken token = confirmationTokenRepository.findByToken(confirmationToken).orElseThrow(() -> new BadRequestException("Unable to confirm email"));
        log.info("Email verification request received for user {}", token.getUser());
        if (new Date().after(new Date(token.getDateCreated().getTime() + CONFIRMATION_TOKEN_EXPIRY_TIME))) {
            throw new BadRequestException("Confirmation link is expired");
        }
        User user = userRepository.findByEmail(token.getUser().getEmail()).orElseThrow(() -> new UsernameNotFoundException("Unable to find the email"));
        user.setEnabled(true);
        userRepository.save(user);

        if (user.isMfaEnabled()){
            return EmailVerificationTokenResponseWs.builder()
                    .message(SUCCESS_RESULT)
                    .secretImageUri(tfaService.generateQrCodeImageUri(user.getSecret()))
                    .build();
        }

        return EmailVerificationTokenResponseWs.builder()
                .message(SUCCESS_RESULT)
                .build();

    }

    @Override
    public AuthenticationResponseWs verifyCode(VerificationRequestWs verificationRequest, HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession(false);
        if (session == null){
            throw new BadRequestException("User is not authenticated!");
        }
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User user = (User) authentication.getPrincipal();
        log.info("Verifying code for user {}", user.getEmail());
        if (tfaService.isNotValidOtp(user.getSecret(), verificationRequest.getCode())){
            throw new BadRequestException("Code is not valid");
        }
        String token = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);
        revokeAllUserToken(user);
        saveUserToken(user, refreshToken);
        session.invalidate();
        setCookies(token, refreshToken,request,response);
        return AuthenticationResponseWs.builder()
                .name(user.getFirstName().concat(" ").concat(user.getLastName()))
                .mfaEnabled(user.isMfaEnabled())
                .build();
    }

    @Override
    public MfaQrCodeResponseWs regenerateMfaQrCode(RegenerateMfaQrCodeRequestWs regenerateMfaQrCode) {
        log.info("Generating MFA QR code for user {}", regenerateMfaQrCode.getEmail());
        User user = userRepository.findByEmail(regenerateMfaQrCode.getEmail()).orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + regenerateMfaQrCode.getEmail()));
        if (!user.isMfaEnabled()){
            throw new BadRequestException("User has not enabled MFA");
        }
        return MfaQrCodeResponseWs.builder()
                .secretImageUri(tfaService.generateQrCodeImageUri(user.getSecret()))
                .build();
    }

    @Override
    public String refreshToken(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = null;
        String newJwtToken = null;
        String newRefreshToken = null;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (REFRESH_TOKEN.equals(cookie.getName())) {
                    refreshToken = cookie.getValue();
                    break;
                }
            }
        }
        RefreshToken refreshTokenDb = tokenRepository.findByToken(refreshToken).orElseThrow(() -> new BadRequestException("Not a valid refresh token"));
        User user = refreshTokenDb.getUser();
        if (jwtService.validateToken(refreshToken, user)) {
            newJwtToken = jwtService.generateToken(user);
            newRefreshToken = jwtService.generateRefreshToken(user);
            revokeAllUserToken(user);
            saveUserToken(user,newRefreshToken);
        }
        setCookies(newJwtToken,newRefreshToken,request,response);
        return "Generated new access token";
    }

    @Override
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        setCookies(null,null,request,response);
        return "Logout Successfully";
    }

    private String generateLink(String token){
        UriComponents uriComponents = UriComponentsBuilder
                .fromHttpUrl(baseUrl)
                .queryParam("token", token)
                .build()
                .encode();

        return uriComponents.toUriString();
    }
    private void saveUserToken(User user, String refreshToken) {
        RefreshToken token = RefreshToken.builder()
                .user(user)
                .token(refreshToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    private void revokeAllUserToken(User user) {
        List<RefreshToken> validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    private void setCookies(String token, String refreshToken, HttpServletRequest request, HttpServletResponse response) {
        long jwtCookieExpiryTime = JWT_COOKIE_EXPIRY_TIME;
        long refreshTokenCookieExpiryTime = REFRESH_TOKEN_COOKIE_EXPIRY_TIME;
        if (token == null && refreshToken == null){
            jwtCookieExpiryTime = 0;
            refreshTokenCookieExpiryTime = 0;
        }
        response.addHeader(SET_COOKIE, String.format("%s=%s; Max-Age=%d; Path=%s; Secure; HttpOnly; SameSite=Strict",
                JWT, token, jwtCookieExpiryTime, request.getContextPath()));
        response.addHeader(SET_COOKIE, String.format("%s=%s; Max-Age=%d; Path=%s; Secure; HttpOnly; SameSite=Strict",
                REFRESH_TOKEN, refreshToken, refreshTokenCookieExpiryTime, request.getContextPath()));
    }
}
