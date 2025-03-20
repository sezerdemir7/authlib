package com.inonu.authlib.exception;

import com.inonu.authlib.dto.RestResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.HttpStatus.BAD_REQUEST;

@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
                                                                  HttpHeaders headers,
                                                                  HttpStatusCode status,
                                                                  WebRequest request) {

        Map<String, String> erors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            erors.put(fieldName, errorMessage);
        });

        return new ResponseEntity<>(erors, BAD_REQUEST);
    }

    @ExceptionHandler(PrivilegeNotFoundException.class)
    public ResponseEntity<RestResponse<String>> handlePrivilegeNotFoundException(PrivilegeNotFoundException exception) {
        return new ResponseEntity<>(RestResponse.error(exception.getMessage()), HttpStatus.NOT_FOUND);
    }
    @ExceptionHandler(PrivilegeException.class)
    public ResponseEntity<RestResponse<String>> handlePrivilegeException(PrivilegeException exception) {
        return new ResponseEntity<>(RestResponse.error(exception.getMessage()), HttpStatus.FORBIDDEN);
    }


}