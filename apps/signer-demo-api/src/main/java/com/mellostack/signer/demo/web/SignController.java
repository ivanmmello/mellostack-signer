package com.mellostack.signer.demo.web;

import com.mellostack.signer.demo.service.SigningSessionService;
import com.mellostack.signer.demo.web.dto.PrepareSignRequest;
import com.mellostack.signer.demo.web.dto.SessionResponse;
import com.mellostack.signer.demo.web.dto.UpdateOptionsRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1/sign")
public class SignController {

    private final SigningSessionService sessionService;
    private final com.mellostack.signer.demo.service.DocumentSigningService signingService;

    public SignController(
            SigningSessionService sessionService,
            com.mellostack.signer.demo.service.DocumentSigningService signingService) {
        this.sessionService = sessionService;
        this.signingService = signingService;
    }

    @PostMapping(value = "/prepare", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public SessionResponse prepare(
            @RequestPart("pdf") MultipartFile pdf,
            @RequestParam(required = false) String provider,
            @RequestParam(required = false) String environment,
            @RequestParam(required = false) String reason,
            @RequestParam(required = false) String location,
            @RequestParam(defaultValue = "false") boolean visibleSignature,
            @RequestParam(defaultValue = "false") boolean timestamp) throws Exception {
        if (pdf.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "PDF file is required");
        }

        PrepareSignRequest request = new PrepareSignRequest(
                provider,
                environment,
                reason,
                location,
                visibleSignature,
                timestamp);

        var session = sessionService.prepare(pdf.getBytes(), pdf.getOriginalFilename(), request);
        return sessionService.toResponse(session);
    }

    @GetMapping("/{sessionId}")
    public SessionResponse getSession(@PathVariable String sessionId) {
        return sessionService.toResponse(sessionService.require(sessionId));
    }

    @PutMapping("/{sessionId}/options")
    public SessionResponse updateOptions(
            @PathVariable String sessionId,
            @RequestBody UpdateOptionsRequest request) {
        return sessionService.toResponse(sessionService.updateOptions(sessionId, request));
    }

    @PostMapping("/{sessionId}/execute")
    public SessionResponse execute(@PathVariable String sessionId) {
        return sessionService.toResponse(signingService.execute(sessionId));
    }

    @GetMapping("/{sessionId}/download")
    public org.springframework.http.ResponseEntity<byte[]> download(@PathVariable String sessionId) {
        var session = sessionService.require(sessionId);
        if (session.signedPdfBytes() == null || session.signedPdfBytes().length == 0) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Signed PDF not available yet");
        }

        String fileName = session.fileName() != null
                ? session.fileName().replace(".pdf", "") + "-signed.pdf"
                : "signed.pdf";

        return org.springframework.http.ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_PDF)
                .header(org.springframework.http.HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"" + fileName + "\"")
                .body(session.signedPdfBytes());
    }
}
