package com.jobexec.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class TestController {

    @GetMapping("/connect")
    public String connect(){
        return "Hello World";
    }

}