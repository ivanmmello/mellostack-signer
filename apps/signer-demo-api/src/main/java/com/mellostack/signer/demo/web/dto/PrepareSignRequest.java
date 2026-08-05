package com.mellostack.signer.demo.web.dto;

public record PrepareSignRequest(
        String provider,
        String environment,
        String reason,
        String location,
        boolean visibleSignature,
        boolean timestamp) {
}
