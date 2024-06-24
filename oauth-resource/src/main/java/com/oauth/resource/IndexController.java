package com.oauth.resource;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

@RestController
public class IndexController {

    @GetMapping("/")
    public String index(@AuthenticationPrincipal Jwt jwt) {
        return String.format("Hello, %s!", jwt.getSubject());
    }

    @GetMapping("/boards")
    public List<Board> message() {
        List<Board> boards = Arrays.asList(
                Board.builder()
                        .userId(UUID.randomUUID().toString())
                        .boardId(1L)
                        .title("Board 1 title")
                        .created(LocalDateTime.now())
                        .build(),
                Board.builder()
                        .userId(UUID.randomUUID().toString())
                        .boardId(2L)
                        .title("Board 2 title")
                        .created(LocalDateTime.now())
                        .build()
        );
        return boards;
    }

    @GetMapping("/board/2")
    @PreAuthorize("hasAuthority('SCOPE_board')")
    public Board board(){
        return Board.builder()
                .userId(UUID.randomUUID().toString())
                .boardId(2L)
                .title("Board 2 title")
                .created(LocalDateTime.now())
                .build();
    }
}
