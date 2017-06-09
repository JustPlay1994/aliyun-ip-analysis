package aliyunApi;

import com.aliyuncs.utils.Base64Helper;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.junit.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.*;

import static com.aliyuncs.auth.AcsURLEncoder.percentEncode;
import static com.aliyuncs.utils.ParameterHelper.getISO8601Time;

/**
 * Created by JustPlay1994 on 2017/6/8.
 * https://github.com/JustPlay1994/daily-log-manager
 */
public class Test2 {

    /**
     * 只调用阿里云的api在进行组串、编码和加密解密
     */

    @Test
    public static void aliAPI(Boolean auto,String action,String accessKeyId, String keySecret, String version,String format,String timestamp,String signatureNonce){
//        log4j
        Logger logger = LogManager.getLogger(Test2.class);
        PropertyConfigurator.configure("src/main/resources/log4j.properties");

//        如果autp=true，使用真正的参数，false则使用构造的固定参数。
        logger.info("auto: "+auto);
        if(auto){
//            自动生成，用于真正调用。上面传餐用于调试，比对结果。
            action = "DescribeDomains";
            accessKeyId="LTAImKyenyClI8EV";
            keySecret="oTMsL9jLrI8ClagbPFSHi9SobjSBxq";
            format="json";
            version="2015-01-09";
            timestamp=getISO8601Time(new Date());
            signatureNonce= UUID.randomUUID().toString();
        }



//        请求url
        String url = "http://alidns.aliyuncs.com/?"; //自带一个?
//        HTTP METHOD
        final String HTTP_METHOD = "GET";
//        组建变量
        Map<String,String> parameters=new HashMap<String,String>();
//        请求参数
        parameters.put("Action",action);
//        公共参数
//        parameters.put("Format","XML");
        parameters.put("Format",format);
//        parameters.put("Version","2015-01-09");
        parameters.put("Version",version);
//        parameters.put("AccessKeyId","LTAImKyenyClI8EV");
        parameters.put("AccessKeyId",accessKeyId);
//        oTMsL9jLrI8ClagbPFSHi9SobjSBxq   ===密码
        parameters.put("SignatureMethod","HMAC-SHA1");
//        parameters.put("Timestamp",getISO8601Time(new Date()));       //取得ISO8601日期
        parameters.put("Timestamp",timestamp);
        parameters.put("SignatureVersion","1.0");
//        parameters.put("SignatureNonce", UUID.randomUUID().toString());  //生成一个随机数
        parameters.put("SignatureNonce", signatureNonce);

        String log="";
        for(Map.Entry<String, String> entry: parameters.entrySet()) {
            log+="("+entry.getKey() + ":" + entry.getValue() + ")\t";
        }
        logger.info("【所有变量的值】: "+log);

//        对参数名进行排序
        String[] sortedKeys = parameters.keySet().toArray(new String[]{});
        Arrays.sort(sortedKeys);
        log = "";
        for (String sortedKey : sortedKeys) {
            log+= sortedKey+", ";
        }
        logger.info("【排序后的串】"+log);

//        生成待签名字符串的前半部分 GET&/ 并进行规范编码
        final String SEPARATOR = "&";

        StringBuilder stringToSign = new StringBuilder();
        stringToSign.append(HTTP_METHOD).append(SEPARATOR);//GET&
        try {
            stringToSign.append(percentEncode("/")).append(SEPARATOR);//GET&%2F
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        logger.info("【待签名前半部分】: "+stringToSign);
//        组成待签名字符串的后半部分，VALUE和KEY分别进行RFC3986编码
        StringBuilder canonicalizedQueryString = new StringBuilder();
        for(String key : sortedKeys) {
            // 这里注意对key和value进行规范化RFC3986编码
            try {
                canonicalizedQueryString.append("&")
                        .append(percentEncode(key)).append("=")
                        .append(percentEncode(parameters.get(key)));
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
        }
        logger.info("【待签名标签后半部分】,对变量名和值分别进行RFC3986规范编码: \n"+canonicalizedQueryString);

//        将 GET&/ 之后的整个串,也就是上面的canonicalizedQueryString进行规范化编码
        try {
            stringToSign.append(percentEncode(canonicalizedQueryString.toString().substring(1)));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        logger.info("【待签名字符串已组完】对整个待签名标签后半部分，进行RFC3986规范编码后，追加到前半部分中: \n"+stringToSign);

//        不处理&符号，得到后半部分字符串。也就是只处理等号！
//        组成待签名字符串的后半部分，VALUE和KEY分别进行RFC3986编码
        StringBuilder canonicalizedQueryString1 = new StringBuilder();
        for(String key : sortedKeys) {
            // 这里注意对key和value进行规范化RFC3986编码
            try {
                canonicalizedQueryString1.append("&")
                        .append(percentEncode(key)).append("%3D")
                        .append(percentEncode(parameters.get(key)));
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
        }
        logger.info("【待签名标签后半部分进行编码】,保留&: \n"+canonicalizedQueryString1);
        StringBuilder stringToSign1 = new StringBuilder("GET&%2F");
        stringToSign1.append(canonicalizedQueryString1);
        logger.info("【待签名字符串组完】,保留了&: \n"+stringToSign1);

//        此时stringToSign即为已组好的待签名字符串

        // 以下是一段计算签名的示例代码，使用HMAC-SHA1算法
        final String ALGORITHM = "HmacSHA1";
        final String ENCODING = "UTF-8";
//        String key = "oTMsL9jLrI8ClagbPFSHi9SobjSBxq&";
        String key = keySecret+"&";
        Mac mac = null;//HMAC-SHA1算法
        try {
//            生成一个指定 Mac 算法 的 Mac 对象 ，传入 算法名称
            mac = Mac.getInstance(ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
//            初始化mac对象，传入 key，以及算法。
            mac.init(new SecretKeySpec(key.getBytes(ENCODING), ALGORITHM));
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        byte[] signData = new byte[0];
        if (mac != null) {
            try {
//                完成加密操作，传入 待签名字符串 即可
                signData = mac.doFinal(stringToSign1.toString().substring(1).getBytes(ENCODING));
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
        }
        logger.info("【Hmac-SHA1】使用的密码是: "+ key+", 使用的编码是: "+ ENCODING+ ", 使用的算法是: "+ ALGORITHM);
        logger.info("【Hmac-SHA1】结果： "+signData);
//        Base64编码
        String signature = new String(Base64Helper.encode(signData));
        logger.info("【将HMAC值进行base64编码后】: "+signature);
//        对url的所有变量和变量名进行过RFC3986编码的 url，包括后加入的Signature，编码是为了避免歧义
        try {
            logger.info("【对所有变量和值分别进行规范化RFC3986编码的url】: \n"+url+canonicalizedQueryString.substring(1)+"&Signature="+percentEncode(signature));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

    }


    public static void main(String[] args){

        aliAPI(true, "DescribeRegions", "testid", "testsecret", "2014-05-26", "XML", "2016-02-23T12:46:24Z", "3ee8c1b8-83d3-44af-a94f-4e0ad82fd6cf");
    }

}

