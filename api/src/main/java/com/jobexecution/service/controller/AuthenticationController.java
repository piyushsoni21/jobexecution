package com.jobexecution.service.controller;

import com.jobexecution.service.AuthenticationService;
import com.jobexecution.service.ws.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public RegistrationResponseWs register(@Valid @RequestBody RegisterRequestWs registerRequest){
        return authenticationService.register(registerRequest);
    }

    @PostMapping("/login")
    public AuthenticationResponseWs login(@Valid @RequestBody LoginRequestWs loginRequest, HttpServletRequest request, HttpServletResponse response){
        return authenticationService.login(loginRequest, request, response);
    }

    @GetMapping("/confirm-email")
    public EmailVerificationTokenResponseWs confirmUserEmail(@RequestParam("token") String token){
        return authenticationService.confirmEmail(token);
    }

    @PostMapping("/verify-mfa-code")
    public AuthenticationResponseWs verifyCode(@RequestBody VerificationRequestWs verificationRequest, HttpServletRequest request, HttpServletResponse response){
        return authenticationService.verifyCode(verificationRequest, request, response);
    }

    @PostMapping("/regenerate-mfa-qr")
    public MfaQrCodeResponseWs regenerateMfaQrCode(@RequestBody RegenerateMfaQrCodeRequestWs regenerateMfaQrCode){
        return authenticationService.regenerateMfaQrCode(regenerateMfaQrCode);
    }

    @PostMapping("/refresh-token")
    public String refreshToken(HttpServletRequest request, HttpServletResponse response){
        return authenticationService.refreshToken(request,response);
    }

    @PostMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response){
        return authenticationService.logout(request,response);
    }
}
