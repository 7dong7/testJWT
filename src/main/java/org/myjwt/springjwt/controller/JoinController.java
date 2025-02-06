package org.myjwt.springjwt.controller;

import lombok.RequiredArgsConstructor;
import org.myjwt.springjwt.dto.JoinDTO;
import org.myjwt.springjwt.service.JoinService;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @PostMapping("/join")
    public String joinProcess(JoinDTO joinDTO) {

        joinService.joinProcess(joinDTO);

        return "ok";
    }
}
