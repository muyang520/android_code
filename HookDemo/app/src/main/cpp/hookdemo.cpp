#include <jni.h>
#include <stdio.h>
#include "md5.h"
#include <string.h>
#include<android/log.h>
#include <string>

#define TAG    "muyang" // 这个是自定义的LOG的标识
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,TAG,__VA_ARGS__) // 定义LOGD类型
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO,TAG,__VA_ARGS__) // 定义LOGI类型
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN,TAG,__VA_ARGS__) // 定义LOGW类型
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,TAG,__VA_ARGS__) // 定义LOGE类型

const char *addString(const char *arg1, const char *arg2) {
    // 将结果转换为 const char* 类型，并返回
    size_t resultLen = strlen(arg1) + strlen(arg2) + 1;
    // 创建目标缓冲区
    char *result = new char[resultLen];
    // 将 str1 复制到目标缓冲区
    strcpy(result, arg1);
    // 使用 strcat() 将 str2 连接到目标缓冲区
    strcat(result, arg2);
    return result;
}


extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_hookdemo_MainActivity_signatureTest(JNIEnv *env, jobject thiz, jstring str) {
    // TODO: implement signatureTest()
    const char *originStr;
    //将jstring转化成char *类型
    originStr = env->GetStringUTFChars(str, JNI_FALSE);
    const char *s = addString(originStr, originStr);

    LOGD("我在JNI层相加%s", s);

    MD5 md5 = MD5(originStr);
    std::string md5Result = md5.hexdigest();
    //将char *类型转化成jstring返回给Java层
    return env->NewStringUTF(md5Result.c_str());

}


extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_hookdemo_MainActivity_teststrstr(JNIEnv *env, jobject thiz) {
    // TODO: implement teststrstr()

    const char haystack[20] = "RUNOOB";
    const char needle[10] = "NOOB";
    const char *string = strstr(haystack, needle);
    LOGD("%s", string);
//    std::cout << "muyang" <<  << std::endl;

    return env->NewStringUTF("md5Result");
}

//public  native String sayHello(String speak);
jstring sayHelloToJNI(JNIEnv *env, jobject thiz, jstring speak) {
    LOGE("我是来自Java层说话的的函数 ->%s", env->GetStringUTFChars(speak, JNI_FALSE));
    return env->NewStringUTF("我是JNI返回来的hello");
}

//public  native int sayNum(int i);
jint addToJNI(JNIEnv *env, jobject thiz, jint a, jint b) {
    return a + b;
}

static const JNINativeMethod nativeMethod[] = {
        {"sayHello", "(Ljava/lang/String;)Ljava/lang/String;", (void *) sayHelloToJNI},
        {"add",      "(II)I",                                  (void *) addToJNI},
};

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    //初始化环境，每一个JNIEnv对应一个线程环境，且JNIEnv不能夸线程使用，如果想要在其他线程中使用JNIEnv则需要给当前线程附加JNIEnv环境
    //vm->AttachCurrentThread(&env,0);//给当前线程附加JNIEnv环境
    //vm->DetachCurrentThread();//分离当前线程环境
    JNIEnv *env = NULL;

    //给JNIEnv环境赋值
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_4) != JNI_OK) {//从JavaVM(java虚拟机)中获取线程的JNIEnv环境
        return JNI_FALSE;
    }
    //获取class对象，classPathName为java类的完整包名+类名
    jclass clazz = env->FindClass("com/example/hookdemo/MainActivity");
    if (clazz == NULL) {
        return JNI_FALSE;
    }
    int result = env->RegisterNatives(clazz, nativeMethod,
                                      sizeof(nativeMethod) / sizeof(nativeMethod[0]));
    //注册Java方法和c++方法的映射关系
    if (result < 0) {
        LOGE("方法映射失败");

    }
    return JNI_VERSION_1_4;
}

std::string jstringToStdString(JNIEnv* env, jstring jstr) {
    if (jstr == NULL) {
        return "";
    }
    char* chars = (char*)env->GetStringUTFChars(jstr, NULL);
    std::string ret(chars);
    env->ReleaseStringUTFChars(jstr, chars);
    return ret;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_hookdemo_MainActivity_tesucanshu_1jni(JNIEnv *env, jobject thiz, jint i,
                                                       jstring two, jintArray array,
                                                       jobject person, jobject listt,
                                                       jobject hashMap,
                                                       jobject stringArray) {
    // TODO: implement tesucanshu_jni()
    //int[] array, Person person, Object listt, Object Sites,Object StringList
    LOGE("jni->args1 ->%d ", i);


    int fenshu = 0;

    //打印int数组
    // 获取数组长度
    int len = env->GetArrayLength(array);

    // 获取数组元素
    jint *elements = env->GetIntArrayElements(array, 0);

    // 打印数组元素
    for (int i = 0; i < len; i++) {
        LOGE("jni->arrar->%d ", elements[i]);
    }

    // 释放数组元素
    env->ReleaseIntArrayElements(array, elements, 0);

    fenshu += 1;

    //调用Person的print对象   考验补环境
    //1得到字节码
    jclass jclazz = env->FindClass("com/example/hookdemo/Person");
    //2得到方法
    jmethodID jmethodIds = env->GetMethodID(jclazz, "getAge", "()I");
    //3实例化
    jobject object = env->AllocObject(jclazz);
    //4调用方法
    int age = env->CallIntMethod(object, jmethodIds);


    //打印 ArrayList  listt
    // 获取 ArrayList 类
    jclass arrayListClass = env->GetObjectClass(listt);

    // 获取 ArrayList.size() 方法
    jmethodID arrayListSize = env->GetMethodID(arrayListClass, "size", "()I");
    if (arrayListSize != NULL) {
        // 调用 ArrayList.size() 方法获取 ArrayList 的大小
        jint size = env->CallIntMethod(listt, arrayListSize);

        // 获取 ArrayList.get() 方法
        jmethodID arrayListGet = env->GetMethodID(arrayListClass, "get", "(I)Ljava/lang/Object;");
        if (arrayListGet != NULL) {
            // 调用 ArrayList.get() 方法获取 ArrayList 中的每个元素并打印
            for (jint i = 0; i < size; i++) {
                jobject elementObject = env->CallObjectMethod(listt, arrayListGet, i);
                jclass elementClass = env->GetObjectClass(elementObject);
                jmethodID toStringMethod = env->GetMethodID(elementClass, "toString",
                                                            "()Ljava/lang/String;");

                // 如果元素有一个 toString 方法，调用它并打印结果
                if (toStringMethod != NULL) {
                    jstring elementString = (jstring) env->CallObjectMethod(elementObject,
                                                                            toStringMethod);
                    const char *cString = env->GetStringUTFChars(elementString, NULL);
                    LOGE("JNI-> Arraylist->%s\n", cString);
                    env->ReleaseStringUTFChars(elementString, cString);
                    fenshu += 1;
                }
            }
        }
    }


    // 获取对象的类
    jclass objClass = env->GetObjectClass(hashMap);

    // 获取 toString 方法 ID
    jmethodID toStringMethod = env->GetMethodID(objClass, "toString", "()Ljava/lang/String;");

    // 调用 toString 方法
    jstring javaString = (jstring) (env->CallObjectMethod(hashMap, toStringMethod));

    // 将 jstring 转换为 C 字符串
    const char *cString = env->GetStringUTFChars(javaString, NULL);

    // 打印字符串
    LOGE("Java String: %s\n", cString);

    // 释放字符串资源
    env->ReleaseStringUTFChars(javaString, cString);


    // 获取数组长度
    jsize arrayLength = env->GetArrayLength(static_cast<jarray>(stringArray));

    for (jsize i = 0; i < arrayLength; ++i) {
        // 获取数组中的每个字符串
        jstring javaString = (jstring) (env->GetObjectArrayElement(
                static_cast<jobjectArray>(stringArray), i));

        // 将Java字符串转换为C字符串
        const char *cString = env->GetStringUTFChars(javaString, NULL);

        // 打印字符串
        LOGE("JNI-> stringlist %s\n", cString);

        // 释放字符串
        env->ReleaseStringUTFChars(javaString, cString);
    }

    std::string s3="闯关失败";
    if(age == 100){
        std::string ret = "恭喜你闯过本关  你输入的第二个参数是";
        std::string s2=jstringToStdString(env,two);
        s3=ret+s2;
    }
    return env->NewStringUTF(s3.c_str());
}
