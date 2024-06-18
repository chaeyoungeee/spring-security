package com.jwt.domain.login;

import com.jwt.domain.login.dto.TokenInfo;
import com.jwt.domain.login.jwt.token.TokenProvider;
import com.jwt.domain.member.Member;
import com.jwt.domain.member.MemberRepository;
import com.jwt.domain.member.Role;
import com.jwt.web.controller.dto.MemberCreateDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.antlr.v4.runtime.Token;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.regex.Pattern;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class LoginService {
    private static final String PASSWORD_REGEX = "^(?=.*[A-Za-z])(?=.*\\d)(?=.*[$@$!%*#?&])[A-Za-z\\d$@$!%*#?&]{8,}$"; //해당 정규표현식을 만족하기 위해서는 최소 8자리 + 영어, 숫자, 특수문자를 모두 포함해야함.
    private static final Pattern PASSWORD_PATTERN = Pattern.compile(PASSWORD_REGEX);
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenProvider tokenProvider;

    public Member createMember(MemberCreateDto memberCreateDto) {
        checkPasswordStrength(memberCreateDto.getPassword());

        if (memberRepository.existsByEmail(memberCreateDto.getEmail())) {
            log.info("이미 등록된 이메일={}", memberCreateDto.getEmail());
            throw new IllegalArgumentException("이미 등록된 이메일입니다.");

        }

        Member member = Member.builder()
                .email(memberCreateDto.getEmail())
                .password(passwordEncoder.encode(memberCreateDto.getPassword()))
                .username(memberCreateDto.getUsername())
                .role(Role.ROLE_USER)
                .build();
        return memberRepository.save(member);
    }

    private void checkPasswordStrength(String password) {
        if (PASSWORD_PATTERN.matcher(password).matches()) {
            return;
        }
        log.info("비밀번호 정책 미달");
        throw new IllegalArgumentException("비밀번호는 최소 8자리에 영어, 숫자, 특수문자를 포함해야 합니다.");
    }


    public TokenInfo loginMember(String email, String password) {
        try {
            Member member = findMemberByEmail(email);

            checkPassword(password, member);

            return tokenProvider.createToken(member);
        } catch (IllegalArgumentException | BadCredentialsException e) {
            throw new IllegalArgumentException("계정이 존재하지 않거나 비밀번호가 잘못되었습니다.");
        }
    }

    public Member getUserInfo(String email) {
        return findMemberByEmail(email); //dto로 변환해야하나 예제의 단순화를 위해 변환안함 -> 수정해라
    }

    private Member findMemberByEmail(String email) {
        return memberRepository.findByEmail(email).orElseThrow(() -> {
            log.info("계정이 존재하지 않음");
            return new IllegalArgumentException("계정이 존재하지 않습니다.");
        });
    }

    private void checkPassword(String password, Member member) {
        if (!passwordEncoder.matches(password, member.getPassword())) {
            log.info("일치하지 않는 비밀번호");
            throw new BadCredentialsException("기존 비밀번호 확인에 실패했습니다.");
        }
    }

}
