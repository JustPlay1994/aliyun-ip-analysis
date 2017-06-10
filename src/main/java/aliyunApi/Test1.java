package aliyunApi;


import com.aliyuncs.utils.Base64Helper;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.log4j.*;
import org.junit.Test;

import org.apache.commons.httpclient.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.aliyuncs.profile.DefaultProfile;
import sun.misc.BASE64Encoder;

import static com.aliyuncs.auth.AcsURLEncoder.percentEncode;

/**
 * Created by JustPlay1994 on 2017/6/7.
 * https://github.com/JustPlay1994/daily-log-manager
 */
public class Test1 {
    Logger logger = LogManager.getLogger(Test1.class);
    @Test
    public void test(){

//        log4j
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
//
//    private static final String ENCODING = "UTF-8";
//    private static String percentEncode(String value) throws UnsupportedEncodingException {
//        return value != null ? URLEncoder.encode(value, ENCODING).replace("+", "%20").replace("*", "%2A").replace("%7E", "~") : null;
//    }

    @Test
    public void aaaaa(){
//        Logger logger = LogManager.getLogger(Test2.class);
//        PropertyConfigurator.configure("src/main/resources/log4j.properties");
//        try {
//            logger.info(URLEncoder.encode("&", "UTF-8"));
//        } catch (UnsupportedEncodingException e) {
//            e.printStackTrace();
//        }

        // 以下是一段计算签名的示例代码，使用HMAC-SHA1算法

        String stringToSign = "GET&%2F&AccessKeyId%3Dtestid&Action%3DDescribeRegions&Format%3DXML&SignatureMethod%3DHMAC-SHA1&SignatureNonce%3D3ee8c1b8-83d3-44af-a94f-4e0ad82fd6cf&SignatureVersion%3D1.0&TimeStamp%3D2016-02-23T12%253A46%253A24Z&Version%3D2014-05-26";
        String keySecret = "testsecret";

        final String ALGORITHM = "HMACSHA1";
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
                signData = mac.doFinal(stringToSign.toString().substring(1).getBytes(ENCODING));
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
        }

        logger.info("【Hmac-SHA1】: ");
        logger.info("明文： "+stringToSign);
        logger.info("密钥： "+keySecret);
        logger.info("HMAC结果： "+signData.toString());
//        logger.info("base64： "+Base64.encodeBase64String(signData););

        try {
            logger.info("阿里base64: "+Base64Helper.encode(signData.toString(),"UTF-8"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
//        logger.info("阿里base64"+ new Base64.Encoder());

//        String base64String = "whuang123";
//        byte[] result = Base64.encodeBase64(base64String.getBytes());


    }

    @Test
    public void xxxxx(){
        String ip = "10.0.1.1";
        CustomSystemUtil customSystemUtil = new CustomSystemUtil();
        ip = customSystemUtil.getInternetIp();
        System.out.println(ip);

        Socket socket = new Socket();

    }

    @Test
    public void tcpip(){
        String server = new String("www.baidu.com");
        int port = 80;
        System.out.println("server: " + server + ", port: " + port);
        try {
            Socket socket = new Socket(server,port);
            System.out.println(socket);
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();

            byte[] data = new String("").getBytes();
            out.write(data);    // Send the encoded string to the server


            // Receive the same string back from the server
            int totalBytesRcvd = 0; // Total bytes received so far
            int bytesRcvd; // Bytes received in last read
            while (totalBytesRcvd < data.length) {
                if ((bytesRcvd = in.read(data, totalBytesRcvd,
                        data.length - totalBytesRcvd)) == -1)
                    try {
                        throw new SocketException("Connection closed prematurely");
                    } catch (SocketException e) {
                        e.printStackTrace();
                    }
                totalBytesRcvd += bytesRcvd;
                System.out.println("Received: " + new String(data));
                socket.close(); // Close the socket and its streams



            } // data array is full
        } catch (IOException e) {
            e.printStackTrace();
        }


    }

    @Test
    public void httpget(){
//        try {
//            HttpClient client = new HttpClient();//定义client对象
//            client.getHttpConnectionManager().getParams().setConnectionTimeout(2000);//设置连接超时时间为2秒（连接初始化时间）
//            GetMethod method = new GetMethod("https://www.baidu.com/s?ie=utf-8&f=8&rsv_bp=1&rsv_idx=2&tn=baiduhome_pg&wd=ip&rsv_spt=1&oq=commons-httpclient-%2526lt%253B.0%2520maven&rsv_pq=c38d2ea00003f0a3&rsv_t=c759jopnYhN2rGZwHD9WR%2FqCZhmDE0UQdHeBEo6bW5DpcxhZRi%2BV7oU5528I56MG1KvP&rqlang=cn&rsv_enter=1&rsv_sug3=24&rsv_sug1=19&rsv_sug7=100&rsv_sug2=0&inputT=327053&rsv_sug4=327054");//百度公网ip
//            int statusCode = 0;//状态，一般200为OK状态，其他情况会抛出如404,500,403等错误
//            try {
//                statusCode = client.executeMethod(method);
//            } catch (IOException e) {
//                e.printStackTrace();
//            }
//            if (statusCode != HttpStatus.SC_OK) {
//                System.out.println("远程访问失败。");
//            }
//            try {
//                String content = method.getResponseBodyAsString();
//                System.out.println(content);//输出反馈结果
//            } catch (IOException e) {
//                e.printStackTrace();
//            }
//            client.getHttpConnectionManager().closeIdleConnections(1);
//        }catch(Exception e){
//            System.out.print(e);
//        }


        try {
            String key = "ip"; //查询关键字
            key = URLEncoder.encode(key, "gb2312");
            URL u1 = new URL("https://www.baidu.com/s?ie=utf-8&f=8&rsv_bp=1&rsv_idx=2&tn=baiduhome_pg&wd=ip&rsv_spt=1&oq=commons-httpclient-%2526lt%253B.0%2520maven&rsv_pq=c38d2ea00003f0a3&rsv_t=c759jopnYhN2rGZwHD9WR%2FqCZhmDE0UQdHeBEo6bW5DpcxhZRi%2BV7oU5528I56MG1KvP&rqlang=cn&rsv_enter=1&rsv_sug3=24&rsv_sug1=19&rsv_sug7=100&rsv_sug2=0&inputT=327053&rsv_sug4=327054" + key + "&cl=3");
            URL u = new URL("http://www.baidu.com.cn/s?wd="+ key + "&cl=3");
            URLConnection conn = u.openConnection();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    conn.getInputStream(), "gb2312"));
            String str = reader.readLine();
            String content="";
            while (str != null) {
                content+=str;
//                System.out.println(str);

                str = reader.readLine();
            }

//            fk="3.3.3.3"
            int a = 0;
            if (content != null) {
                a = content.indexOf("fk=\"");
            }

            int i=a;

            String ip = "";
            while(true){
                if(content.charAt(i)=='\"'){
                    while(true){
                        i++;
                        if(content.charAt(i)=='\"'){
                            break;
                        }
                        ip+=content.charAt(i);
                    }
                    break;
                }
                i++;

            }
            System.out.println(ip);

            reader.close();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    @Test
    public static void main(String[] args){
        // run in a second
        final long timeInterval = 10000;
        Runnable runnable = new Runnable() {
            public void run() {
                while (true) {
                    // ------- code for task to run
                    System.out.println("Hello !!");
                    // ------- ends here
                    try {
                        Thread.sleep(timeInterval);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            }
        };
        Thread thread = new Thread(runnable);
        thread.start();
    }

}
