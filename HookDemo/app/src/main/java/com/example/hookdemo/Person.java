package com.example.hookdemo;
import java.security.MessageDigest;
import android.util.Log;

 abstract class Animal{
    static int anonymoutInt = 500;
    int ceshi = 999;
    public abstract void eatFunc(String value);
}

class Person {

    private String name = "chushidezhi";
    private static int age = 50;
    public  static String address = "小说";
    private static String ceshi = "我是测试字段";
    private static String print = "我是print字段";


    public Person() {
    }

    public Person(String name) {
        this();
        this.name = name;
    }

    public Person(String name, int age) {
        this(name);
        this.age = age;
    }

    public Person(String name, int age,String address) {
        this(name);
        this.age = age;
        this.address = address;
    }

    public void setName(String name) {
        // this.name指的是当前对象Person的name
        // name指的是传入的参数
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public void setAge(int age) {
        this.age = age;
    }

    public int getAge() {
        return age;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public void print() {
        Log.d("muyang","Person的属性为:"+this.name+" "+this.age +" "+this.address);
    }

    private void print(String name,int age,String address){
        Log.d("muyang","Person的属性为:"+name+" "+age +" "+address);
    }

    public static void print(String name,int age){
        Log.d("muyang","Person没有address的属性为:"+name+" "+age);
    }



    class People {
        public String name = "xiaoming";
        public People(){
        }
        public People(String name){
            this.name = name;
            Log.d("muyang","传进来的是:"+name);
        }
        public void print() {
            Log.d("muyang","内部类的名称:"+this.name);
        }
        public void print(String name,int age,String address) {
            Log.d("muyang","People的内部类属性为:"+name+" "+age +" "+address);
        }
    }

    public void nimingfangfa1(){
        Animal a = new Animal() {
            @Override
            public void eatFunc(String value) {
                Log.d("muyang", "eatFunc(String value)  was called|||" + value);
                Log.d("muyang", "anonymoutInt =  " + anonymoutInt + "ceshi ="+ceshi);
            }
        };
      a.eatFunc("fish");
    }

    public void nimingfangfa2(){
        Animal a = new Animal() {
            @Override
            public void eatFunc(String value) {
                Log.d("muyang", "eatFunc(String value)  was called|||" + value);
                Log.d("muyang", "anonymoutInt =  " + anonymoutInt);
            }
        };
        a.eatFunc("fish");
    }
}
