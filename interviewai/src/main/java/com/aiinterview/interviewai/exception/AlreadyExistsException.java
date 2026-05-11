package com.aiinterview.interviewai.exception;

public class AlreadyExistsException extends RuntimeException{
    public AlreadyExistsException(String message){
        super((message));
    }
}