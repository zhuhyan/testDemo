package com.example.testdemo.AES;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

/**
 * @author:zhuhongyan
 * @date:2025/7/23 10:33
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final String APP_KEY = "1d5337d4-06a6-4654-80d4-826b5cfe823b";
    private static final String KEY = "epEaE3UehAoX2tZJ"; // 与加密算法中保持一致

    /**
     * 验证 header 中的 AppID 和 Token 是否有效
     */
    @PostMapping("/check")
    public ResponseEntity verifyToken(@RequestHeader("AppID") String appId,
                                         @RequestHeader("Token") String token) {
        try {
            if (!APP_KEY.equals(appId)) {
                return ResponseEntity.status(401).body("AppID 不合法");
            }

            // 构建当前时间 ±2分钟范围内的可能 Token
            boolean valid = false;
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

            for (int i = -2; i <= 2; i++) {
                String timeStr = LocalDateTime.now().plusMinutes(i).format(formatter);
                String source = KEY + timeStr;
                String expectedToken = EncryptUtils.aesEncrypt(source, KEY);
                if (expectedToken.equals(token)) {
                    valid = true;
                    break;
                }
            }

            if (!valid) {
                return ResponseEntity.status(401).body("Token 不合法或过期");
            }

            // 验证通过，返回成功内容
            Map<String, Object> result = new HashMap<>();
            result.put("code", 200);
            result.put("msg", "认证成功");
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("服务异常: " + e.getMessage());
        }
    }

    /**
     * 获取当前有效 Token
     */
    @GetMapping("/token")
    public ResponseEntity getToken() {
        try {
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
            String timeStr = LocalDateTime.now().format(formatter);
            String source = APP_KEY + timeStr;
            String token = EncryptUtils.aesEncrypt(source, KEY);
            Map<String, String> result = new HashMap<>();
            result.put("Token", token);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("生成 Token 失败: " + e.getMessage());
        }
    }
}
