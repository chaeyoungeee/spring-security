package com.jwt.web.controller.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED) //스프링이 json을 파싱해 dto에 담아줄 수 있도록 함
public class MemberCreateDto {
    @Email
    private String email;

    @NotNull
    private String password;

    @NotEmpty
    private String username;


}
