package com.example.gatewayservice.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
public class DiscoveryDebugController {

    @Autowired
    private DiscoveryClient discoveryClient;

    @GetMapping("/discovery")
    public ResponseEntity<?> discoveryStatus() {
        List<String> services = discoveryClient.getServices();
        List<ServiceInstance> instances = discoveryClient.getInstances("auth-service");
        return ResponseEntity.ok(Map.of(
                "services", services,
                "auth-service-instances", instances
        ));
    }
}