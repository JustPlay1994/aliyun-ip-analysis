package aliyunApi;

import com.aliyuncs.utils.Base64Helper;
import org.apache.log4j.*;
import org.junit.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.*;


/**
 * Created by JustPlay1994 on 2017/6/7.
 * https://github.com/JustPlay1994/daily-log-manager
 */
public class Test1 {
    Logger logger = LogManager.getLogger(Test1.class);
    @Test
    public void test(){
        PropertyConfigurator.configure("src/main/resources/log4j.properties");

        final String HTTP_METHOD = "GET";
        Map<String, String> parameters = new HashMap<String, String>();
        // 加入请求参数
        parameters.put("Action", "DescribeDomains");
        parameters.put("Version", "2015-01-09");
        parameters.put("AccessKeyId", "LTAImKyenyClI8EV");
        parameters.put("TimeStamp", formatIso8601Date(new Date()));
        parameters.put("SignatureMethod", "HMAC-SHA1");
        parameters.put("SignatureVersion", "1.0");
        parameters.put("SignatureNonce", UUID.randomUUID().toString());
        parameters.put("Format", "json");
        // 对参数进行排序
        String[] sortedKeys = parameters.keySet().toArray(new String[]{});
        Arrays.sort(sortedKeys);
        final String SEPARATOR = "&";
        // 生成stringToSign字符串
        StringBuilder stringToSign = new StringBuilder();
        stringToSign.append(HTTP_METHOD).append(SEPARATOR);
        try {
            stringToSign.append(percentEncode("/")).append(SEPARATOR);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        StringBuilder canonicalizedQueryString = new StringBuilder();
        for(String key : sortedKeys) {
            // 这里注意对key和value进行编码
            try {
                canonicalizedQueryString.append("&")
                        .append(percentEncode(key)).append("=")
                        .append(percentEncode(parameters.get(key)));
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
        }
        logger.info("canonicalizedQueryString(key-value编码)： " + canonicalizedQueryString);
        String test = new String(canonicalizedQueryString);
        // 这里注意对canonicalizedQueryString进行编码
        try {
            stringToSign.append(percentEncode(
                    canonicalizedQueryString.toString().substring(1)));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        logger.info("stringToSign(用于签名的字符串): " + stringToSign);


        // 以下是一段计算签名的示例代码
        final String ALGORITHM = "HmacSHA1";
        final String ENCODING = "UTF-8";
        String key = "oTMsL9jLrI8ClagbPFSHi9SobjSBxq&";
        Mac mac = null;
        try {
            mac = Mac.getInstance(ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            mac.init(new SecretKeySpec(key.getBytes(ENCODING), ALGORITHM));
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        byte[] signData = new byte[0];

        String str = stringToSign.toString();
        try {
            signData = mac.doFinal(str.getBytes(ENCODING));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        logger.info("keysecret: "+key);
        logger.info("HMAC值："+signData);
//        String signature = new String(Base64.encodeBase64(signData));
        String signature = new String(Base64Helper.encode(signData));

        logger.info("Signature(base64编码后)=" + signature);
        String signature_1=null;
        try {
            signature_1=percentEncode(signature);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        logger.info("signature编码后= "+signature_1);
        String test1 = test.substring(1, test.length());
        logger.info("https://alidns.aliyuncs.com/?"+test1+"&Signature="+signature_1);
    }

    private static final String ISO8601_DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss'Z'";
    private static String formatIso8601Date(Date date) {
        SimpleDateFormat df = new SimpleDateFormat(ISO8601_DATE_FORMAT);
        df.setTimeZone(new SimpleTimeZone(0, "GMT"));
        return df.format(date);
    }

    private static final String ENCODING = "UTF-8";
    private static String percentEncode(String value) throws UnsupportedEncodingException {
        return value != null ? URLEncoder.encode(value, ENCODING).replace("+", "%20").replace("*", "%2A").replace("%7E", "~") : null;
    }
}
