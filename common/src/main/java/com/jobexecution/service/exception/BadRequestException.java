package com.jobexecution.service.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class BadRequestException extends RuntimeException{
    private final HttpStatus httpStatus;

    public BadRequestException(String message){
        super(message);
        this.httpStatus = HttpStatus.BAD_REQUEST;
    }

    public BadRequestException(String message, Throwable error) {
        super(message, error);
        this.httpStatus = HttpStatus.BAD_REQUEST;
    }

    public BadRequestException(String message, HttpStatus httpStatus) {
        super(message);
        this.httpStatus = httpStatus;
    }
}
