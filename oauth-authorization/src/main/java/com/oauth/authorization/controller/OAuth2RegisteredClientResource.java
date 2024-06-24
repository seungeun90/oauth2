package com.oauth.authorization.controller;

import com.oauth.authorization.domain.OauthClient;
import com.oauth.authorization.service.service.OAuth2RegisteredClientService;
import com.oauth.authorization.controller.dto.RegisteredClientRequest;
import com.oauth.authorization.controller.dto.RegisteredClientResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/oauth2")
public class OAuth2RegisteredClientResource {

    private final OAuth2RegisteredClientService registeredClientService;

    /**
     * @return
     */
    @PostMapping("/registration")
    @ResponseStatus(HttpStatus.OK)
    public @ResponseBody ResponseEntity<?> register(@RequestBody RegisteredClientRequest request) {
        OauthClient registered = registeredClientService.save(new OauthClient(request.getClientName(),
                 request.getRedirectUris(), request.getScopes()));
        return ResponseEntity.ok(new RegisteredClientResponse(registered.getClientId(), registered.getClientSecret()));
    }

}
