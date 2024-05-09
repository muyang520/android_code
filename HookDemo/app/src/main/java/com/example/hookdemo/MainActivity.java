package com.example.hookdemo;

import androidx.appcompat.app.AppCompatActivity;
import android.Manifest;
import android.app.Application;
import android.content.Context;
import android.os.Build;
import android.os.Bundle;
import android.system.ErrnoException;
import android.system.Os;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.TextView;

import java.io.DataOutputStream;
import java.lang.reflect.Array;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.UUID;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {
    static {
        System.loadLibrary("hookdemo");
    }

    private String TAG = "muyang";

    private native String signatureTest(String params_);

    private native String teststrstr();


    public native String sayHello(String speak);

    public native int add(int a, int b);

    public native String tesucanshu_jni(int i, String two, int[] array, Person person, Object listt, Object Sites, Object StringList);

    public native String sha1(String str);
    public static native String aesEncryptECB(byte[] bytes);
    public static native byte[] aesDecryptECB(String str);

    public native String getHash(String str);

    public native String jiance_xp_frida();
    public native void xitongdiaoyong();

    //函数调用链相关
    //此函数用来做多个初始化动作
    public native void main(int i);

    //此函数用来返回各个字段名称
    public native String main1(int i);

    //最终的加密函数
    public native String callchushihua1();
    public native String callchushihua2();

    private TextView textView;

    @Override
    protected void attachBaseContext(Context newBase) {
        super.attachBaseContext(newBase);
    }

    private Person person1;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        findViewById(R.id.btn_putongfangfa).setOnClickListener(this);
        findViewById(R.id.btn_neibuleifangfa).setOnClickListener(this);
        findViewById(R.id.btn_xiugaishuxing).setOnClickListener(this);
        findViewById(R.id.btn_tihuanhanshu).setOnClickListener(this);
        findViewById(R.id.btn_zhudongdiaoyong).setOnClickListener(this);
        findViewById(R.id.btn_diaoyongsohanshu).setOnClickListener(this);
        findViewById(R.id.btn_diaoyongstr).setOnClickListener(this);
        findViewById(R.id.btn_fuzashujuleixing).setOnClickListener(this);
        findViewById(R.id.btn_diaoyongchongzai).setOnClickListener(this);
        findViewById(R.id.unidbg_fuzhacanshu).setOnClickListener(this);
        findViewById(R.id.huoquapkhash).setOnClickListener(this);
        findViewById(R.id.jiancefrida).setOnClickListener(this);
        findViewById(R.id.xitongbianliang).setOnClickListener(this);
        findViewById(R.id.chushihua).setOnClickListener(this);
        findViewById(R.id.chushihua2).setOnClickListener(this);

        person1 = new Person("全局muyang", 20, "中国");
        textView = findViewById(R.id.testviewmd5);

        sayHello("muyang");
        Log.d("muyang", "加法" + add(1, 2));

        //进行初始化
        main(1);
        main(2);
        main(3);
        main(4);
    }

    public void showlog(String msg) {
        Log.d(TAG, msg);
    }

    public void tesucanshu(int[] array, Person person, ArrayList<String> listt, Object Sites) {

        Log.d("muyang", String.valueOf(array.getClass()));
        showlog("进入特殊参数函数");

        Log.d("muyang", Arrays.toString(array));
        //打印array
        // 打印所有数组元素
        for (int i : array) {
            showlog(i + " ");
        }
        //调用person的print方法
        person.print();
        //打印list
        showlog(listt.toString());
        //打印Sites
        showlog(Sites.toString());

    }


    public void tesucanshu(int[] array, Person person, ArrayList<String> listt, Object Sites, Object[] StringList) {

        showlog("进入特殊参数函数重载");

        Log.d("muyang", Arrays.toString(array));
        //打印array
        // 打印所有数组元素
        for (int i : array) {
            showlog(i + " ");
        }
        //调用person的print方法
        person.print();
        //打印list
        showlog(listt.toString());
        //打印Sites
        showlog(Sites.toString());

        Log.d("muyang", String.valueOf(Arrays.toString(StringList)));
    }


    public static boolean RootCommand(String command)
    {
        Process process = null;
        DataOutputStream os = null;
        try
        {
            process = Runtime.getRuntime().exec("su");
            os = new DataOutputStream(process.getOutputStream());
            os.writeBytes(command + "\n");
            os.writeBytes("exit\n");
            os.flush();
            process.waitFor();
        } catch (Exception e)
        {
            Log.d("*** DEBUG ***", "ROOT REE" + e.getMessage());
            return false;
        } finally
        {
            try
            {
                if (os != null)
                {
                    os.close();
                }
                process.destroy();
            } catch (Exception e)
            {
            }
        }
        Log.d("*** DEBUG ***", "Root SUC ");
        return true;
    }
    public void tesucanshu2(int[] array, Person person, Object listt, Object Sites, Object StringList) {

        showlog("进入特殊参数函数2");

        Log.d("muyang", Arrays.toString(array));
        //打印array
        // 打印所有数组元素
        for (int i : array) {
            showlog(i + " ");
        }
        //调用person的print方法
        person.print();
        //打印list
        showlog(listt.toString());
        //打印Sites
        showlog(Sites.toString());


        Log.d("muyang", String.valueOf(Arrays.toString(new Object[]{StringList})));
        for (int i = 0; i < Array.getLength(StringList); i++) {
            Log.d("muyang", (String) Array.get(StringList, i));

        }
        Log.d("muyang", String.valueOf(StringList.getClass()));
    }


    @Override
    public void onClick(View v) {

        if (v.getId() == R.id.btn_putongfangfa) {
            Person person = new Person("muyang", 20, "中国");
            Log.d("muyang", "返回名称:" + person.getName());
        } else if (v.getId() == R.id.btn_neibuleifangfa) {
            Person person = new Person("muyang", 20, "中国");

            //内部类方法
            Person.People people = person.new People("内部muyang");
            people.print();

            //匿名类方法
            person.nimingfangfa1();
        } else if (v.getId() == R.id.btn_xiugaishuxing) {

            person1.print();

            Person person = new Person();
            person.print();

            //内部类属性
            Person.People people = person1.new People();
            people.print();


            //匿名内部类
            person1.nimingfangfa1();

        } else if (v.getId() == R.id.btn_zhudongdiaoyong) {
            person1.print();
        } else if (v.getId() == R.id.btn_tihuanhanshu) {
            person1.print();

            Person.print("张三", 100);
        } else if (v.getId() == R.id.btn_diaoyongsohanshu) {
            String string = signatureTest("muyang");
            textView.setText("md5结果" + string);

            Log.d("muyang", sayHello("muyang"));
            Log.d("muyang", "加法" + add(1, 2));
        } else if (v.getId() == R.id.btn_diaoyongstr) {
            teststrstr();
        } else if (v.getId() == R.id.btn_fuzashujuleixing) {
            //数组类型 https://www.runoob.com/java/java-array.html
            int[] shuzu = new int[]{3, 1, 2, 6, 4, 2};
            //对象类型
            Person duixiang = new Person("奥特曼", 100, "M78星云");
            //ArrayList:https://blog.csdn.net/Yqf745873310/article/details/106739535
            ArrayList<String> list = new ArrayList<>();
            list.add("关羽");
            list.add("张飞");
            list.add("赵云");
            list.add("马超");
            list.add("黄忠");

            //HashMap:	https://m.runoob.com/java/java-hashmap.html?ivk_sa=1024320u
            // 创建 HashMap 对象 Sites
            HashMap<Integer, String> Sites = new HashMap<Integer, String>();
            // 添加键值对
            Sites.put(1, "Google");
            Sites.put(2, "Runoob");
            Sites.put(3, "Taobao");
            Sites.put(4, "Zhihu");

            tesucanshu(shuzu, duixiang, list, Sites);
        } else if (v.getId() == R.id.btn_diaoyongchongzai) {
            Person duixiang2 = new Person();
            duixiang2.setAddress("中国");
            duixiang2.setAge(20);
            duixiang2.setName("张三");

            duixiang2.print();

            Person.print("奥特曼2", 100);

            Log.d("muyang", duixiang2.getName());

            //数组类型 https://www.runoob.com/java/java-array.html
            int[] shuzu = new int[]{3, 1, 2, 6, 4, 2};
            //对象类型
            Person duixiang1 = new Person("奥特曼", 100, "M78星云");
            //ArrayList:https://blog.csdn.net/Yqf745873310/article/details/106739535
            ArrayList<String> list = new ArrayList<>();
            list.add("关羽");
            list.add("张飞");
            list.add("赵云");
            list.add("马超");
            list.add("黄忠");

            //HashMap:	https://m.runoob.com/java/java-hashmap.html?ivk_sa=1024320u
            // 创建 HashMap 对象 Sites
            HashMap<Integer, String> Sites = new HashMap<Integer, String>();
            // 添加键值对
            Sites.put(1, "Google");
            Sites.put(2, "Runoob");
            Sites.put(3, "Taobao");
            Sites.put(4, "Zhihu");

            String[] listString = new String[]{"nihao", "shijie"};
            tesucanshu(shuzu, duixiang1, list, Sites, listString);
            tesucanshu2(shuzu, duixiang1, list, Sites, listString);

        } else if (v.getId() == R.id.unidbg_fuzhacanshu) {

            //数组类型 https://www.runoob.com/java/java-array.html
            int[] shuzu = new int[]{3, 1, 2, 6, 4, 2};
            //对象类型
            Person duixiang1 = new Person("JNI奥特曼", 100, "来自JNI的奥特曼");
            Log.d(TAG, "进入unidbg复杂参数调用"+duixiang1.getName());

            ArrayList<String> list = new ArrayList<>();
            list.add("JNI关羽");
            list.add("JNI张飞");
            list.add("JNI赵云");
            list.add("JNI马超");
            list.add("JNI黄忠");

            // 创建 HashMap 对象 Sites
            HashMap<Integer, String> Sites = new HashMap<Integer, String>();
            // 添加键值对
            Sites.put(1, "Google");
            Sites.put(2, "Runoob");
            Sites.put(3, "Taobao");
            Sites.put(4, "Zhihu");

            String[] listString = new String[]{"nihao", "shijie"};
            textView.setText(tesucanshu_jni(12345678, "nihao", shuzu, duixiang1, list, Sites, listString));

            Log.d(TAG,"SHA1加密"+sha1("你好"));
            Log.d(TAG,"aes加密"+aesEncryptECB("你好".getBytes()));
            Log.d(TAG,"aes解密"+ new String(aesDecryptECB(aesEncryptECB("你好".getBytes()))));

        } else if (v.getId()==R.id.huoquapkhash) {
            Log.d(TAG,getApplicationContext().getPackageCodePath());
            textView.setText("当前apkhash值= "+getHash(getApplicationContext().getPackageCodePath()));
        }else if(v.getId() == R.id.jiancefrida){
            textView.setText(jiance_xp_frida());
        }else if(v.getId() == R.id.xitongbianliang){
            Log.d(TAG,"进来");
            try {
                Os.setenv("muyang","6666",true);
            } catch (ErrnoException e) {
                throw new RuntimeException(e);
            }
            xitongdiaoyong();
        }else if(v.getId() == R.id.chushihua){
            textView.setText(callchushihua1());
            Utils util = new Utils();
            Log.d(TAG, String.valueOf(util.isWifiProxy(getApplicationContext())));
            Log.d(TAG, String.valueOf(util.isVpnConnectionActive(getApplicationContext())));
            Log.d(TAG, "是否开启autojs无障碍:"+String.valueOf(util.isAccessibilityServiceEnabled(this, "com.stardust.scriptdroid.accessibility.AccessibilityService")));

            Log.d(TAG, "是否具有电话权限:"+util.hasPermission(this, Manifest.permission.CAMERA));
            Log.d(TAG, "是否具有访问网络权限:"+util.hasPermission(this, Manifest.permission.ACCESS_NETWORK_STATE));
            Log.d(TAG, "是否具有访问Wi-Fi权限:"+util.hasPermission(this, Manifest.permission.ACCESS_WIFI_STATE));

            Log.d(TAG,"当前包名->"+main1(1));
            Log.d(TAG,"当前SDK版本->"+main1(2));
            Log.d(TAG,"内存->"+util.getTotalStorageSizeInGB());


        }else if(v.getId() == R.id.chushihua2){
            textView.setText(callchushihua2());

            UUID randomUUID = UUID.fromString("befc5388-ea1d-41b5-9494-66517aeb7630");
            ByteBuffer wrap = ByteBuffer.wrap(new byte[16]);
            wrap.putLong(randomUUID.getMostSignificantBits());
            wrap.putLong(randomUUID.getLeastSignificantBits());
            Base64.encodeToString(wrap.array(),11);
        }
    }
}