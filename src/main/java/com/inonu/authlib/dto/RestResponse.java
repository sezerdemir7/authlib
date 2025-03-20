package com.inonu.authlib.dto;

import com.fasterxml.jackson.annotation.JsonFormat;

import java.io.Serializable;
import java.time.LocalDateTime;

public class RestResponse<T> implements Serializable {
    private T data;
    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS")
    private LocalDateTime responseDate;
    private Boolean success;
    private String message;

    public RestResponse(T data, Boolean success) {
        this.data = data;
        this.success = success;
        this.message = success ? "Operation completed successfully." : "";
        this.responseDate=LocalDateTime.now();
    }

    public static <T> RestResponse<T> of(T t){
        return new RestResponse(t, true);
    }
    public static <T> RestResponse<T> error(T t){
        return new RestResponse(t, false);
    }
    public static <T> RestResponse<T> empty(){return new RestResponse<>(null,true);}

    public RestResponse() {
    }

    public T getData() {
        return data;
    }

    public void setData(T data) {
        this.data = data;
    }

    public LocalDateTime getResponseDate() {
        return responseDate;
    }

    public void setResponseDate(LocalDateTime responseDate) {
        this.responseDate = responseDate;
    }

    public Boolean getSuccess() {
        return success;
    }

    public void setSuccess(Boolean success) {
        this.success = success;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}

