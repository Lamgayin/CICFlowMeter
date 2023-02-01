package cic.cs.unb.ca.jnetpcap.worker;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.util.*;

import org.json.JSONObject;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;

public class PostFlowData implements Runnable {
    public static final Logger logger = LoggerFactory.getLogger(PostFlowData.class);
    private String header;
    private List<String> rows;
    private String url = null;
    private static String apikeyPath="./apikey.txt";
    private String apikey = null;
    public PostFlowData(String header, List<String> rows, String url) {
        this.header = header;
        this.rows = rows;
        this.url = url;
    }

    public PostFlowData(String header, String row, String url) {
        this.header = header;
        this.rows = new ArrayList<>();
        this.url = url;
        rows.add(row);
    }

    @Override
    public void run() {
        insert(header,rows,url);
    }

    public static void insert(String header,List<String> rows,String url) {

        if (header == null || rows == null || rows.size() <= 0 || url==null ) {
            String ex = String.format("header=%s,url=%s", header,url);
            throw new IllegalArgumentException(ex);
        }

        try {
            String[] featuresHeader = header.split(",");
            String[] element = rows.get(0).split(",");
            String key=readAPIKEY(apikeyPath);

            Map dict = new HashMap();

            for(int i=0;i<featuresHeader.length;i++){
                dict.put(featuresHeader[i], element[i]);
            };

            dict.put("apikey",key);

            JSONObject json = new JSONObject(dict);
            doPost(url,json);

        } catch (Exception e) {
                logger.debug(e.getMessage());
        }
    }

    public static void doPost(String url,JSONObject json){

        HttpClient httpclient = new DefaultHttpClient();
        try {
            HttpPost request = new HttpPost(url);
            request.setHeader("Content-Type", "application/json");
            // Request body
            StringEntity reqEntity = new StringEntity(String.valueOf(json),"UTF-8");
            request.setEntity(reqEntity);
            System.out.println(request.toString());
            HttpResponse response = httpclient.execute(request);
            HttpEntity entity = response.getEntity();

            String temp = EntityUtils.toString(entity);
            System.out.println("status:"+temp);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static String readAPIKEY(String path){
        BufferedReader br = null;
        StringBuffer sb = null;
        String key = null;
        try{
            br=new BufferedReader(new InputStreamReader(new FileInputStream(path),"GBK"));
            sb=new StringBuffer();
            String line=null;
            while((line=br.readLine())!=null){
                sb.append(line);
            }
            key=new String(sb);
        }catch (Exception e){
            logger.debug(e.getMessage());
        }

        return key;
    }
}
