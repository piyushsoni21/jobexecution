package com.jobexecution.service.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class JobExecutionException extends RuntimeException{
    private final HttpStatus httpStatus;

    public JobExecutionException(String message){
        super(message);
        this.httpStatus = HttpStatus.INTERNAL_SERVER_ERROR;
    }

    public JobExecutionException(String message, Throwable throwable){
        super(message);
        this.httpStatus = HttpStatus.INTERNAL_SERVER_ERROR;
    }

    public JobExecutionException(String message, HttpStatus httpStatus){
        super(message);
        this.httpStatus = httpStatus;
    }
}
