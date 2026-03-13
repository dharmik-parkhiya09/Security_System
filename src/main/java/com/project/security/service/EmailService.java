package com.project.security.service;

import com.project.security.entity.User;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;

    @Value("${spring.mail.username}")
    private String fromEmail;

    @Async
    public void sendEmail(String to,
                          String subject,
                          String name,
                          String message,
                          String actionUrl,
                          String buttonText) throws MessagingException {

        Context context = new Context();
        context.setVariable("name", name);
        context.setVariable("subject", subject);
        context.setVariable("message", message);
        context.setVariable("actionUrl", actionUrl);
        context.setVariable("buttonText", buttonText);

        String html = templateEngine.process("email-template", context);

        MimeMessage mimeMessage = mailSender.createMimeMessage();
        MimeMessageHelper helper =
                new MimeMessageHelper(mimeMessage, true, "UTF-8");

        helper.setTo(to);
        helper.setSubject(subject);
        helper.setText(html, true);
        helper.setFrom(fromEmail);

        mailSender.send(mimeMessage);

        log.info("Email sent successfully to {}", to);
    }

    public void sendVerificationEmail(User user, String token) throws MessagingException {
        String verifyUrl = "http://localhost:8083/auth/verify?token=" + token;
        sendEmail(
                user.getEmail(),
                "Verify Your Account",
                user.getUsername(),
                "Please click the button below to verify your account.",
                verifyUrl,
                "Verify Account"
        );
    }

    public void sendLoginAlertEmail(User user) throws MessagingException {
        sendEmail(
                user.getEmail(),
                "New Login Detected",
                user.getUsername(),
                "A new login was detected in your account.",
                "http://localhost:8083/index.html",
                "Go to Dashboard"
        );
    }

    public void sendResetPasswordEmail(User user, String token) throws MessagingException {

        String resetUrl = "http://localhost:8083/index.html?resetToken=" + token;
        sendEmail(
                user.getEmail(),
                "Reset Your Password",
                user.getUsername(),
                "Click the button below to reset your password.",
                resetUrl,
                "Reset Password"
        );
    }


    private void sendEmail(String to,
                           String subject,
                           String name,
                           String actionUrl,
                           String buttonText,
                           String ip,
                           String device,
                           String loginTime) throws MessagingException {

        Context context = new Context();
        context.setVariable("name",       name);
        context.setVariable("subject",    subject);
        context.setVariable("message",    null);      // suppresses the plain-text block
        context.setVariable("actionUrl",  actionUrl);
        context.setVariable("buttonText", buttonText);
        context.setVariable("ip",         ip);
        context.setVariable("device",     device);
        context.setVariable("loginTime",  loginTime);

        String html = templateEngine.process("email-template", context);

        MimeMessage mimeMessage = mailSender.createMimeMessage();
        MimeMessageHelper helper =
                new MimeMessageHelper(mimeMessage, true, "UTF-8");

        helper.setTo(to);
        helper.setSubject(subject);
        helper.setText(html, true);
        helper.setFrom(fromEmail);

        mailSender.send(mimeMessage);

        log.info("Login alert email sent successfully to {}", to);
    }


    public void sendLoginAlertEmail(User user, String ip, String device, String loginTime)
            throws MessagingException {

        sendEmail(
                user.getEmail(),
                "New Login Detected on Your Account",
                user.getUsername(),
                "http://localhost:8083/index.html",
                "Go to My Account",
                ip,
                device,
                loginTime
        );
    }


}