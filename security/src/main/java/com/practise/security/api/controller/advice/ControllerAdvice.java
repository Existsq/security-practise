package com.practise.security.api.controller.advice;

import com.practise.security.api.dto.ErrorResponse;
import com.practise.security.domain.exception.UserAlreadyExistsException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@RestControllerAdvice
public class ControllerAdvice {

  @ResponseStatus(HttpStatus.BAD_REQUEST)
  @ExceptionHandler
  public ErrorResponse handleUserAlreadyExists(UserAlreadyExistsException e) {
    log.error("UserAlreadyExistsException: {}", e.getMessage(), e);
    return new ErrorResponse("Credentials Error", e.getMessage());
  }
}
