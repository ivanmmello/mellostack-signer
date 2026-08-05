package com.mellostack.signer.demo;

import com.mellostack.signer.demo.config.DemoProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(DemoProperties.class)
public class SignerDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(SignerDemoApplication.class, args);
    }
}
