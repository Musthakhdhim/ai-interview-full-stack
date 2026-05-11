package com.aiinterview.interviewai.exception;

public class PasswordNotMatchException extends RuntimeException{
    public PasswordNotMatchException(String message){
        super(message);
    }
}