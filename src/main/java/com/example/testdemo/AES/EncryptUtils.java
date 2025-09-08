package com.example.testdemo.AES;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Base64;

/**
 * @author:zhuhongyan
 * @date:2025/7/23 10:30
 */
public class EncryptUtils {
    private static final String SECRET = "AES";
    private static final String CIPHER_ALGORITHM = "AES/ECB/PKCS7Padding";
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * AES 加密，使用 ECB 模式 + PKCS7Padding
     * @param plainText 明文字符串
     * @param key 密钥（长度需为16/24/32字节）
     * @return Base64编码后的密文
     * @throws Exception 异常信息
     */
    public static String aesEncrypt(String plainText, String key) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM, "BC");
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, SECRET);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }
    /**
     * AES 解密，使用 ECB 模式 + PKCS7Padding
     * @param cipherText Base64编码的密文
     * @param key 密钥
     * @return 解密后的明文字符串
     * @throws Exception 异常信息
     */
    public static String aesDecrypt(String cipherText, String key) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM, "BC");
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, SECRET);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] decodedBytes = Base64.getDecoder().decode(cipherText);
        byte[] decrypted = cipher.doFinal(decodedBytes);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

}
