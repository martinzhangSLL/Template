package com.rgs.core.util;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @auther: lgq
 * @time: 2019/9/19 16:34
 * @description:
 */
@Slf4j
@Service
public class AESUtil {

    //秘钥
    private static String KEY = "zkcfqflllxgqyzlz";
    //偏移量
    private static String IV = "lzyzgqlxllqfcfzk";


    /**
     * 加密返回的数据转换成 String 类型
     *
     * @param content 明文
     * @return
     * @throws Exception
     */
    public static String encrypt(String content){
        try{
            // 将返回的加密过的 byte[] 转换成Base64编码字符串 ！！！！很关键
            // "utf-8" 解决中文乱码问题
            return base64ToString(AES_CBC_Encrypt(content.getBytes("utf-8"), KEY.getBytes(), IV.getBytes()));
        }catch (Exception e){
            log.error("数据加密异常:{}",e.getMessage());
        }
        return null;
    }


    /**
     * 将解密返回的数据转换成 String 类型
     *
     * @param content Base64编码的密文
     * @return
     * @throws Exception
     */
    public static String decrypt(String content){
        try {
            // stringToBase64() 将 Base64编码的字符串转换成 byte[] !!!与base64ToString(）配套使用
            // "utf-8" 解决中文乱码问题
            return new String(AES_CBC_Decrypt(stringToBase64(content), KEY.getBytes(), IV.getBytes()),"utf-8");
        }catch (Exception e){
            log.error("数据解密异常:{}",e.getMessage());
        }
        return null;
    }

    /**
     * 加密
     * @param content
     * @param keyBytes
     * @param iv
     * @return
     * @throws Exception
     */
    private static byte[] AES_CBC_Encrypt(byte[] content, byte[] keyBytes, byte[] iv) throws Exception {
        try {
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] result = cipher.doFinal(content);
            return result;
        } catch (Exception e) {
            throw new Exception("字符串加密失败");
        }
    }

    /**
     * 解密
     * @param content
     * @param keyBytes
     * @param iv
     * @return
     * @throws Exception
     */
    private static byte[] AES_CBC_Decrypt(byte[] content, byte[] keyBytes, byte[] iv) throws Exception {
        try {
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] result = cipher.doFinal(content);
            return result;
        } catch (Exception e) {
            throw new Exception("字符串解密失败");
        }
    }

    /**
     * 字符串装换成 Base64
     */

    public static byte[] stringToBase64(String key) throws Exception {
        return Base64.decodeBase64(key.getBytes());
    }

    /**
     * Base64装换成字符串
     */
    public static String base64ToString(byte[] key) throws Exception {
        return new Base64().encodeToString(key);
    }
}
