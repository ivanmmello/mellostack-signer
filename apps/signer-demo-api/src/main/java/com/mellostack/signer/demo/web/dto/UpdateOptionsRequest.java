package com.mellostack.signer.demo.web.dto;

public record UpdateOptionsRequest(
        String reason,
        String location,
        boolean visibleSignature,
        boolean timestamp) {
}
