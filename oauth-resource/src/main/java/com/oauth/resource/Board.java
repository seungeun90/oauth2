package com.oauth.resource;

import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
@Builder
public class Board {
    private String userId;
    private Long boardId;
    private String title;
    private LocalDateTime created;
}
