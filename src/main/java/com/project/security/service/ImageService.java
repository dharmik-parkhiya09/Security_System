package com.project.security.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

@Service
@Slf4j
public class ImageService {

    private static final String UPLOAD_DIR = "uploads/profile";

    public String uploadProfileImage(Long userId, MultipartFile file) throws IOException {

        Path uploadPath = Paths.get(UPLOAD_DIR);
        Files.createDirectories(uploadPath);

        String ext = StringUtils.getFilenameExtension(file.getOriginalFilename());
        if (ext == null || !ext.matches("(?i)jpg|jpeg|png|gif|webp")) {
            throw new IllegalArgumentException("Unsupported image format: " + ext);
        }

        try (var stream = Files.list(uploadPath)) {
            stream
                    .filter(Files::isRegularFile)
                    .filter(p -> {
                        String name = p.getFileName().toString().toLowerCase();
                        return name.startsWith("user_" + userId + "_")
                                || name.contains("_" + userId + "_")
                                || name.contains("_" + userId + ".");
                    })
                    .forEach(p -> {
                        try {
                            Files.deleteIfExists(p);
                            log.info("Deleted old profile image: {}", p.getFileName());
                        } catch (IOException e) {
                            log.warn("Could not delete old profile image: {}", p);
                        }
                    });
        }

        String filename = "user_" + userId + "_profile." + ext.toLowerCase();
        Path filePath = uploadPath.resolve(filename);
        Files.copy(file.getInputStream(), filePath, StandardCopyOption.REPLACE_EXISTING);
        log.info("Saved profile image for user {}: {}", userId, filename);

        return filename;
    }
}