package com.jobexecution.service;

import com.jobexecution.service.ws.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface AuthenticationService {
    RegistrationResponseWs register(RegisterRequestWs registerRequest);
    AuthenticationResponseWs login(LoginRequestWs loginRequest, HttpServletRequest request, HttpServletResponse response);
    EmailVerificationTokenResponseWs confirmEmail(String confirmationToken);
    AuthenticationResponseWs verifyCode(VerificationRequestWs verificationRequest, HttpServletRequest request, HttpServletResponse response);
    MfaQrCodeResponseWs regenerateMfaQrCode(RegenerateMfaQrCodeRequestWs regenerateMfaQrCode);
    String refreshToken(HttpServletRequest request, HttpServletResponse response);
    String logout(HttpServletRequest request,HttpServletResponse response);

}
