package com.mellostack.signer.demo.web;

import com.mellostack.signer.demo.service.OAuthFlowService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.net.URI;

@RestController
@RequestMapping("/api/v1/oauth")
public class OAuthController {

    private final OAuthFlowService oauthFlowService;

    public OAuthController(OAuthFlowService oauthFlowService) {
        this.oauthFlowService = oauthFlowService;
    }

    @GetMapping("/authorize")
    public ResponseEntity<Void> authorize(@RequestParam String sessionId) {
        try {
            URI target = oauthFlowService.startAuthorization(sessionId);
            return ResponseEntity.status(HttpStatus.FOUND)
                    .header(HttpHeaders.LOCATION, target.toString())
                    .build();
        } catch (IllegalStateException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ex.getMessage(), ex);
        }
    }

    @GetMapping("/callback")
    public ResponseEntity<Void> callback(
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String state,
            @RequestParam(required = false) String error,
            @RequestParam(name = "error_description", required = false) String errorDescription) {
        if (state == null || state.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing OAuth state (session id)");
        }

        if (error != null && !error.isBlank()) {
            String message = errorDescription != null ? errorDescription : error;
            URI redirect = oauthFlowService.failureRedirect(state, message);
            return redirect(redirect);
        }

        if (code == null || code.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing authorization code");
        }

        try {
            URI redirect = oauthFlowService.completeAuthorization(state, code);
            return redirect(redirect);
        } catch (RuntimeException ex) {
            URI redirect = oauthFlowService.failureRedirect(state, ex.getMessage());
            return redirect(redirect);
        }
    }

    private static ResponseEntity<Void> redirect(URI target) {
        return ResponseEntity.status(HttpStatus.FOUND)
                .header(HttpHeaders.LOCATION, target.toString())
                .build();
    }
}
