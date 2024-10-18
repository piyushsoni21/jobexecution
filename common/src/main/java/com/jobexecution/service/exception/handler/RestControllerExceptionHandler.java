package com.jobexecution.service.exception.handler;

import com.jobexecution.service.exception.BadRequestException;
import com.jobexecution.service.exception.dto.ErrorDto;
import com.jobexecution.service.exception.dto.ErrorsDto;
import io.jsonwebtoken.JwtException;
import lombok.extern.log4j.Log4j2;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.List;

@RestControllerAdvice
@Log4j2
public class RestControllerExceptionHandler extends ResponseEntityExceptionHandler {
    @ExceptionHandler(BadRequestException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorsDto handleBadRequest(BadRequestException badRequestException, WebRequest webRequest) {
        return buildResponseBody(badRequestException, HttpStatus.BAD_REQUEST.value(), HttpStatus.BAD_REQUEST.getReasonPhrase(), badRequestException.getMessage());
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex, HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        List<String> errorMessages = ex.getBindingResult().getFieldErrors().stream()
                .map(FieldError::getDefaultMessage)
                .toList();
        String detailedErrorMessage = String.join(", ", errorMessages);

        return ResponseEntity.status(HttpStatus.BAD_REQUEST.value()).body(buildResponseBody(ex, HttpStatus.BAD_REQUEST.value(), "Invalid Request", detailedErrorMessage));
    }

    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(HttpMessageNotReadableException ex, HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST.value()).body(buildResponseBody(ex, HttpStatus.BAD_REQUEST.value(), "Invalid Request", ex.getMessage()));
    }

    @ExceptionHandler(DataAccessException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public ErrorsDto handleDataAccessException(DataAccessException e) {
        String message = "Some error occurred!";
        if (e.getCause() != null && e.getCause().getCause() != null) {
            String causeMessage = e.getCause().getCause().getMessage();
            if (causeMessage.contains("duplicate key value violates unique constraint")) {
                String field = extractFieldName(causeMessage);
                message = "The value provided for the field '" + field + "' already exists.";
            }
            if (causeMessage.contains("violates foreign key constraint")){
                message = "Unable to delete or update this item because it is associated with other data.";
            }
        }
        return buildResponseBody(e, HttpStatus.CONFLICT.value(), HttpStatus.CONFLICT.getReasonPhrase(), message);
    }

    @ExceptionHandler(AuthenticationException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ErrorsDto handleAuthenticationException(AuthenticationException e){
        return buildResponseBody(e, HttpStatus.UNAUTHORIZED.value(), "Invalid credentials", e.getMessage());
    }

    @ExceptionHandler(JwtException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public ErrorsDto handleJwtException(JwtException e){
        return buildResponseBody(e, HttpStatus.FORBIDDEN.value(), "Forbidden user", e.getMessage());
    }

    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ErrorsDto handleOtherException(Exception exception) {
        return buildResponseBody(exception, HttpStatus.INTERNAL_SERVER_ERROR.value(), HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase(), exception.getMessage());
    }

    private ErrorsDto buildResponseBody(Exception exception, int status, String errorMessage, String detailedErrorMessage) {
        log.error(exception.getLocalizedMessage(), exception);
        return ErrorsDto.builder()
                    .error(ErrorDto.builder()
                            .reasonCode(String.valueOf(status))
                            .description(errorMessage)
                            .details(detailedErrorMessage)
                            .build())
                    .build();

    }

    private String extractFieldName(String causeMessage) {
        return causeMessage.substring(causeMessage.indexOf("(") + 1, causeMessage.indexOf(")"));
    }
}
