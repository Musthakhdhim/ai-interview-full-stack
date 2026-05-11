package com.aiinterview.interviewai.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Welcomecontroller {

    @GetMapping("/hello")
    public String hello(){
        return "hello";
    }


}
