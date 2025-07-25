package com.practise.security.api.dto;

import lombok.Data;

@Data
public class CredentialsRequest {
  private String email;
  private String password;
}
