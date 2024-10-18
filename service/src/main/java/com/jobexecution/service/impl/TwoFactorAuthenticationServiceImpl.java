package com.jobexecution.service.impl;

import dev.samstevens.totp.code.*;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

import static dev.samstevens.totp.util.Utils.getDataUriForImage;

@Service
@Log4j2
public class TwoFactorAuthenticationServiceImpl {

    public String generateNewSecret() {
        return new DefaultSecretGenerator().generate();
    }

    public String generateQrCodeImageUri(String secret) {
        QrData data = new QrData.Builder()
                .label("Job Execution")
                .secret(secret)
                .issuer("JOB EXECUTION")
                .algorithm(HashingAlgorithm.SHA1)
                .digits(6)
                .period(30)  // 30 Seconds
                .build();

        QrGenerator generator = new ZxingPngQrGenerator();
        byte[] imageData;
        try {
            imageData = generator.generate(data);
        } catch (QrGenerationException e) {
            throw new RuntimeException("Error while generating QR Code - "+ e.getMessage());
        }
        return getDataUriForImage(imageData, generator.getImageMimeType());
    }

    public boolean isValidOtp(String secret, String code){
        TimeProvider timeProvider = new SystemTimeProvider();
        CodeGenerator codeGenerator = new DefaultCodeGenerator();
        CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
        return verifier.isValidCode(secret, code);
    }

    public boolean isNotValidOtp(String secret, String code){
        return !this.isValidOtp(secret,code);
    }

}
