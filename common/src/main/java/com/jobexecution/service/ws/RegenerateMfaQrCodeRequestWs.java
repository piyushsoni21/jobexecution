package com.jobexecution.service.ws;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RegenerateMfaQrCodeRequestWs {
    private String email;
}
