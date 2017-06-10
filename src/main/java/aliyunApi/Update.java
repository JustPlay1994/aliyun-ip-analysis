package aliyunApi;

import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.IAcsClient;
import com.aliyuncs.alidns.model.v20150109.*;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.exceptions.ServerException;
import com.aliyuncs.profile.DefaultProfile;
import com.aliyuncs.profile.IClientProfile;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.util.List;

/**
 * Created by JustPlay1994 on 2017/6/10.
 * https://github.com/JustPlay1994/daily-log-manager
 */

public class Update {
    static Logger logger = LogManager.getLogger(Update.class);

    private static IAcsClient client = null;
    static {
        //        log4j
        PropertyConfigurator.configure("src/main/resources/log4j.properties");


        String regionId = "cn-hangzhou"; //必填固定值，必须为“cn-hanghou”
        String accessKeyId = "LTAImKyenyClI8EV"; // your accessKey
        String accessKeySecret = "oTMsL9jLrI8ClagbPFSHi9SobjSBxq";// your accessSecret
        IClientProfile profile = DefaultProfile.getProfile(regionId, accessKeyId, accessKeySecret);
        // 若报Can not find endpoint to access异常，请添加以下此行代码
        // DefaultProfile.addEndpoint("cn-hangzhou", "cn-hangzhou", "Alidns", "alidns.aliyuncs.com");
        client = new DefaultAcsClient(profile);
    }


    public static Boolean updatePulibIp(){
        DescribeDomainRecordsRequest describeDomainRecordsRequest = new DescribeDomainRecordsRequest();
        describeDomainRecordsRequest.setDomainName("justplay1994.win");
        DescribeDomainRecordsResponse recordsResponse;

        // describeRegionsRequest.setProtocol(ProtocolType.HTTPS); //指定访问协议
        // describeRegionsRequest.setAcceptFormat(FormatType.JSON); //指定api返回格式
        // describeRegionsRequest.setMethod(MethodType.POST); //指定请求方法
        // describeRegionsRequest.setRegionId("cn-hangzhou");//指定要访问的Region,仅对当前请求生效，不改变client的默认设置。

        DescribeDomainRecordsResponse.Record id1=null;
        DescribeDomainRecordsResponse.Record id2=null;
        String publicIp = "";


        try {
            String key = "ip"; //查询关键字
            key = URLEncoder.encode(key, "gb2312");
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

            publicIp = "";
            while(true){
                if(content.charAt(i)=='\"'){
                    while(true){
                        i++;
                        if(content.charAt(i)=='\"'){
                            break;
                        }
                        publicIp+=content.charAt(i);
                    }
                    break;
                }
                i++;

            }
            logger.info("当前公网ip: "+publicIp);

            reader.close();
        } catch (Exception ex) {
            ex.printStackTrace();
        }


//查询ip
        try {
            recordsResponse = client.getAcsResponse(describeDomainRecordsRequest);
            List<DescribeDomainRecordsResponse.Record> list = recordsResponse.getDomainRecords();
            for (DescribeDomainRecordsResponse.Record record : list) {
                logger.info("name: "+record.getDomainName()+", id: "+record.getRecordId()+", value: "+record.getValue()+", RR: "+record.getRR()+", type: "+record.getType());
            }
            id1 = list.get(0);
            id2 = list.get(1);
        } catch (ServerException e) {
            e.printStackTrace();
        } catch (ClientException e) {
            e.printStackTrace();
        }

        if(id1.getValue().equals(publicIp)){
            return false;
        }
//        更新ip
        UpdateDomainRecordRequest updateDomainRecordRequest = new UpdateDomainRecordRequest();
        UpdateDomainRecordResponse updateDomainRecordResponse;
        updateDomainRecordRequest.setRecordId(id1.getRecordId());
        updateDomainRecordRequest.setRR(id1.getRR());
        updateDomainRecordRequest.setActionName("UpdateDomainRecord");
        updateDomainRecordRequest.setTTL(id1.getTTL());
        updateDomainRecordRequest.setType(id1.getType());
        updateDomainRecordRequest.setValue(publicIp);
        try{
            updateDomainRecordResponse = client.getAcsResponse(updateDomainRecordRequest);
            logger.info(updateDomainRecordResponse.getRecordId() + " " + updateDomainRecordResponse.getRequestId() + " ");
        }catch (ServerException e){
            e.printStackTrace();
        }catch (ClientException e) {
            e.printStackTrace();
        }

        UpdateDomainRecordRequest updateDomainRecordRequest1 = new UpdateDomainRecordRequest();
        UpdateDomainRecordResponse updateDomainRecordResponse1;
        updateDomainRecordRequest1.setRecordId(id2.getRecordId());
        updateDomainRecordRequest1.setRR(id2.getRR());
        updateDomainRecordRequest1.setActionName("UpdateDomainRecord");
        updateDomainRecordRequest1.setTTL(id2.getTTL());
        updateDomainRecordRequest1.setType(id2.getType());
        updateDomainRecordRequest1.setValue(publicIp);
        try{
            updateDomainRecordResponse1 = client.getAcsResponse(updateDomainRecordRequest1);
            logger.info(updateDomainRecordResponse1.getRecordId() + " " + updateDomainRecordResponse1.getRequestId() + " ");
        }catch (ServerException e){
            e.printStackTrace();
        }catch (ClientException e) {
            e.printStackTrace();
        }
        return true;
    }

    static long number =0;
    static long updateNumber =0;
    public static void main(String[] args) {


        final long timeInterval = 10000;
        Runnable runnable = new Runnable() {
            public void run() {
                while (true) {
                    // ------- code for task to run
                    number++;
                    if(updatePulibIp()){
                        updateNumber++;
                    }
                    logger.info("执行次数：" + number + "/ 修改ip次数：" +updateNumber);
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
