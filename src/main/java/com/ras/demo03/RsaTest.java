package com.ras.demo03;

import com.sun.org.apache.xml.internal.security.utils.Base64;

import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * RSA使用X509EncodedKeySpec、PKCS8EncodedKeySpec生成公钥和私钥
 *
 * Created by miaokun on 2016/7/19.
 */
public class RsaTest {

    private static final String KEY_ALGORITHM = "RSA";
    private static final String PUBLIC_KEY ="publicKey";
    private static final String PRIVATE_KEY ="privateKey";

    public static void main(String[] args) throws Exception{
        Map<String,String> keyMap = genKey();
        RSAPublicKey publicKey = getPublicKey(keyMap.get(PUBLIC_KEY));
        RSAPrivateKey privateKey = getPrivateKey(keyMap.get(PRIVATE_KEY));
        String info ="明文12345678907890";
        //加密
        byte[] bytes = encrypt(info.getBytes("utf-8"),publicKey);
        System.out.println(new String(bytes,"utf-8"));
        //解密
        bytes = decrypt(bytes, privateKey);
        System.out.println(new String(bytes,"utf-8"));

    }

    /**
     * 加密
     *
     * @param bytes
     * @param publicKey
     * @return
     */
    public static byte[] encrypt(byte[] bytes, RSAPublicKey publicKey) {
        if (publicKey != null) {
            try {
                Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
                cipher.init(Cipher.ENCRYPT_MODE, publicKey);
                return cipher.doFinal(bytes);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return null;
    }


    /**
     * 解密
     * @param bytes
     * @param privateKey
     * @return
     */
    public static byte[] decrypt(byte[] bytes, RSAPrivateKey privateKey) {
        if (privateKey != null) {
            try {
                Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
                cipher.init(Cipher.DECRYPT_MODE, privateKey);
                return cipher.doFinal(bytes);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    /**
     * 获得密钥对，编码成String后存入map
     *
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static Map<String,String> genKey() throws NoSuchAlgorithmException {
        Map<String,String> keyMap = new HashMap<String,String>();
        KeyPairGenerator keygen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        SecureRandom random = new SecureRandom();
        // 初始加密，512位已被破解，用1024位,最好用2048位
        keygen.initialize(1024, random);
        // 取得密钥对
        KeyPair kp = keygen.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey)kp.getPrivate();
        String privateKeyString = Base64.encode(privateKey.getEncoded());//编码成String
        RSAPublicKey publicKey = (RSAPublicKey)kp.getPublic();
        String publicKeyString = Base64.encode(publicKey.getEncoded());//编码成String
        keyMap.put(PUBLIC_KEY, publicKeyString);
        keyMap.put(PRIVATE_KEY, privateKeyString);
        return keyMap;
    }

    /**
     * 获得公钥
     *
     * @param publicKey
     * @return
     * @throws Exception
     */
    public static RSAPublicKey getPublicKey(String publicKey) throws Exception{
        //解码
        byte[] keyBytes = Base64.decode(publicKey);
        //X509EncodedKeySpec编码
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        return (RSAPublicKey) keyFactory.generatePublic(spec);
    }

    /**
     * 获得私钥
     *
     * @param privateKey
     * @return
     * @throws Exception
     */
    public static RSAPrivateKey getPrivateKey(String privateKey) throws Exception{
        //解码
        byte[] keyBytes = Base64.decode(privateKey);
        //PKCS8EncodedKeySpec编码
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        return (RSAPrivateKey) keyFactory.generatePrivate(spec);
    }


}
