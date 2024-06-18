package com.jwt.web.controller.json;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.springframework.http.HttpStatus;

@Getter
@ToString
@NoArgsConstructor
public class ApiResponseJson { //응답을 API 스펙에 맞게 JSON으로 변환하기 위한 클래스
    public HttpStatus httpStatus;
    public int code;
    public Object data;

    public ApiResponseJson(HttpStatus httpStatus, int code, Object data) { //오류 발생
        this.httpStatus = httpStatus;
        this.code = code;
        this.data = data;
    }

    public ApiResponseJson(HttpStatus httpStatus, Object data) { //정상
        this.httpStatus = httpStatus;
        this.code = ResponseStatusCode.OK;
        this.data = data;
    }

}
