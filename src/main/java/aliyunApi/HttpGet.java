package aliyunApi;

import org.junit.Test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
/**
 * Created by JustPlay1994 on 2017/6/10.
 * https://github.com/JustPlay1994/daily-log-manager
 */

public class HttpGet {
    String host = "www.javathinker.org";
    int port = 80;
    Socket socket;

    public void createSocket() throws Exception {
        socket = new Socket("www.baidu.com", 80);
    }

    public void communicate() throws Exception {
        StringBuffer sb = new StringBuffer("GET / HTTP/1.1/r/n");
        sb.append("Host: <A href=\"www.baidu.com\" mce_href=\"www.baidu.com\" target=_blank>www.baidu.com</A>/r/n");
        sb.append("Connection: Keep-Alive/r/n");
        sb.append("Accept: */*/r/n/r/n");

        // 发出HTTP请求
        OutputStream socketOut = socket.getOutputStream();
        socketOut.write(sb.toString().getBytes());
        socket.shutdownOutput(); // 关闭输出流

        // 接收响应结果
        System.out.println(socket);

        InputStream socketIn = socket.getInputStream();
        BufferedReader br = new BufferedReader(new InputStreamReader(socketIn));
        String data;
        while ((data = br.readLine()) != null) {
            System.out.println(data);
        }
        socket.close();
    }

    @Test
    public void testtsts(){
        HttpGet client = new HttpGet();
        try {
            client.createSocket();
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            client.communicate();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
