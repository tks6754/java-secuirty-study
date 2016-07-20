package com.ras.demo04;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;

/**
 * Created by miaokun on 2016/7/19.
 */
public class RSATest {
    public static void main(String[] args) throws Exception {
        HashMap<String, Object> map = RSAUtils.getKeys();
        //生成公钥和私钥
        RSAPublicKey publicKey = (RSAPublicKey) map.get("public");
        RSAPrivateKey privateKey = (RSAPrivateKey) map.get("private");

        //模
        String modulus = publicKey.getModulus().toString();
        //公钥指数
        String public_exponent = publicKey.getPublicExponent().toString();
        //私钥指数
        String private_exponent = privateKey.getPrivateExponent().toString();
        //明文
        String ming = "123456789";
        //使用模和指数生成公钥和私钥
        RSAPublicKey pubKey = RSAUtils.getPublicKey(modulus, public_exponent);
        //true
        System.out.println(pubKey.equals(publicKey));

        RSAPrivateKey priKey = RSAUtils.getPrivateKey(modulus, private_exponent);
        //false ??不太理解为什么要再次通过modulus和exponent取key，而且取得的key，公钥与keyPair取得的相同，但私钥却不同
        System.out.println(priKey.equals(privateKey));

        //加密后的密文
        String mi = RSAUtils.encryptByPublicKey(ming, pubKey);
        System.err.println(mi);
        //解密后的明文
        ming = RSAUtils.decryptByPrivateKey(mi, priKey);
        System.err.println(ming);
    }
}
