#include <jni.h>
#include <stdio.h>
#include "md5.h"
#include <string.h>
#include<android/log.h>
#include <string>
#include "utils.cpp"

#include "sha1.h"
#include "aes.h"
static const uint8_t AES_KEY[] = "xS544RXNm0P4JVLHIEsTqJNzDbZhiLjr";

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

std::string jstringToStdString(JNIEnv *env, jstring jstr) {
    if (jstr == NULL) {
        return "";
    }
    char *chars = (char *) env->GetStringUTFChars(jstr, NULL);
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

    //3unidbg 构造 AllocObject
    jobject object = env->AllocObject(jclazz);


    //2得到方法
    jmethodID jmethodIds = env->GetMethodID(jclazz, "getAge", "()I");
    //4调用方法
    int age = env->CallIntMethod(person, jmethodIds);

    //2得到方法
    jmethodID jmethodId_name = env->GetMethodID(jclazz, "getName", "()Ljava/lang/String;");

    //4.unidbg处理 返回为字符串的
    jstring nameobj = (jstring) (env->CallObjectMethod(person, jmethodId_name));
    // 将 jstring 转换为 C 字符串
    const char *nameobjString = env->GetStringUTFChars(nameobj, NULL);
    // 打印字符串
    LOGE("Java nameobjString String: %s\n", nameobjString);


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

    // 获取 toString 方法 ID   unidbg处理返回值string
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


    char *sha1 = getSha1(env, getGlobalContext(env));
    jboolean result = checkValidity(env, sha1);


    std::string s3 = "闯关失败";
    if (age == 100 && result) {
        std::string ret = "恭喜你闯过本关  你输入的第二个参数是";
        std::string s2 = jstringToStdString(env, two);
        s3 = ret + s2;
    }
    return env->NewStringUTF(s3.c_str());
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_hookdemo_MainActivity_sha1(JNIEnv *env, jobject thiz, jstring str1) {
    // TODO: implement sha1()

    const char * plaintextChar = env->GetStringUTFChars(str1, 0);
    std::string plaintextStr = std::string(plaintextChar);

    SHA1 sha1;
    std::string sha1String = sha1(plaintextStr);
    char * tabStr = new char [sha1String.length()+1];
    strcpy(tabStr, sha1String.c_str());

    char sha1Result[128] = {0};
    formatSignature(tabStr, sha1Result);
    return env->NewStringUTF(sha1Result);
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_hookdemo_MainActivity_aesEncryptECB(JNIEnv *env, jclass clazz, jbyteArray jbArr) {
    // TODO: implement aesEncrypt()
    char *str = NULL;
    jsize alen = env->GetArrayLength(jbArr);
    jbyte *ba = env->GetByteArrayElements(jbArr, JNI_FALSE);
    str = (char *) malloc(alen + 1);
    memcpy(str, ba, alen);
    str[alen] = '\0';
    env->ReleaseByteArrayElements(jbArr, ba, 0);

    char *result = AES_ECB_PKCS7_Encrypt(str, AES_KEY);//AES ECB PKCS7Padding加密
//    char *result = AES_CBC_PKCS7_Encrypt(str, AES_KEY, AES_IV);//AES CBC PKCS7Padding加密
    return env->NewStringUTF(result);

}
extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_hookdemo_MainActivity_aesDecryptECB(JNIEnv *env, jclass clazz, jstring out_str) {
    // TODO: implement aesDecrypt_ECB()
    const char *str = env->GetStringUTFChars(out_str, 0);
    char *result = AES_ECB_PKCS7_Decrypt(str, AES_KEY);//AES ECB PKCS7Padding解密
//    char *result = AES_CBC_PKCS7_Decrypt(str, AES_KEY, AES_IV);//AES CBC PKCS7Padding解密 弱检验不建议使用
    env->ReleaseStringUTFChars(out_str, str);

    jsize len = (jsize) strlen(result);
    jbyteArray jbArr = env->NewByteArray(len);
    env->SetByteArrayRegion(jbArr, 0, len, (jbyte *) result);
    return jbArr;
}

jbyteArray convertByteArrayToJByteArray(JNIEnv* env, const jbyte* byteArray, int length) {
    jbyteArray jbyteArrayObject = env->NewByteArray(length);
    env->SetByteArrayRegion(jbyteArrayObject, 0, length, byteArray);

    return jbyteArrayObject;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_hookdemo_MainActivity_getHash(JNIEnv *env, jobject thiz, jstring apk_path) {
    // TODO: implement getHash()
    const char* apkPath = env->GetStringUTFChars(apk_path, NULL);

    // 获取Java类和方法的引用
    jclass zipFileClass = env->FindClass("java/util/zip/ZipFile");
    jmethodID openMethod = env->GetMethodID(zipFileClass, "<init>", "(Ljava/lang/String;)V");
    jmethodID entriesMethod = env->GetMethodID(zipFileClass, "entries", "()Ljava/util/Enumeration;");
    jclass enumerationClass = env->FindClass("java/util/Enumeration");
    jmethodID hasMoreElementsMethod = env->GetMethodID(enumerationClass, "hasMoreElements", "()Z");
    jmethodID nextElementMethod = env->GetMethodID(enumerationClass, "nextElement", "()Ljava/lang/Object;");
    jclass zipEntryClass = env->FindClass("java/util/zip/ZipEntry");
    jmethodID getNameMethod = env->GetMethodID(zipEntryClass, "getName", "()Ljava/lang/String;");
    jmethodID getInputStreamMethod = env->GetMethodID(zipFileClass, "getInputStream", "(Ljava/util/zip/ZipEntry;)Ljava/io/InputStream;");
    jclass inputStreamClass = env->FindClass("java/io/InputStream");
    jmethodID readMethod = env->GetMethodID(inputStreamClass, "read", "([B)I");
    jmethodID closeMethod = env->GetMethodID(inputStreamClass, "close", "()V");

    // 创建ZipFile对象并打开APK文件
    jobject zipFileObj = env->NewObject(zipFileClass, openMethod, apk_path);
    if (zipFileObj == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, "JNI", "Failed to open APK file");
        env->ReleaseStringUTFChars(apk_path, apkPath);
        return NULL;
    }

    // 获取ZipFile的entries方法并调用
    jobject entriesObj = env->CallObjectMethod(zipFileObj, entriesMethod);
    if (entriesObj == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, "JNI", "Failed to get entries");
        env->DeleteLocalRef(zipFileObj);
        env->ReleaseStringUTFChars(apk_path, apkPath);
        return NULL;
    }

    // 遍历ZipFile中的每个条目并计算MD5值
    jboolean hasMoreElements = env->CallBooleanMethod(entriesObj, hasMoreElementsMethod);

// 获取MessageDigest类和DigestUtils类的引用
    jclass messageDigestClass = env->FindClass("java/security/MessageDigest");
    jmethodID getInstanceMethod = env->GetStaticMethodID(messageDigestClass, "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    // 获取MD5哈希值
    jstring algorithm = env->NewStringUTF("MD5");
    jobject messageDigestObj = env->CallStaticObjectMethod(messageDigestClass, getInstanceMethod, algorithm);

    jmethodID md5update = env->GetMethodID(messageDigestClass, "update", "([B)V");
    jmethodID md5digest = env->GetMethodID(messageDigestClass, "digest", "()[B");



    while (hasMoreElements) {
        jobject zipEntryObj = env->CallObjectMethod(entriesObj, nextElementMethod);
        if (zipEntryObj != NULL) {
            jstring nameObj = (jstring) env->CallObjectMethod(zipEntryObj, getNameMethod);
            const char* entryName = env->GetStringUTFChars(nameObj, NULL);

            // 获取ZipEntry对应的InputStream对象
            jobject inputObj = env->CallObjectMethod(zipFileObj, getInputStreamMethod, zipEntryObj);
            if (inputObj != NULL) {
                // 读取InputStream中的数据并更新MD5值
                jbyteArray bufferObj = env->NewByteArray(4096);
                jbyte* buffer = env->GetByteArrayElements(bufferObj, NULL);
                jint bytesRead;
                while ((bytesRead = env->CallIntMethod(inputObj, readMethod, bufferObj)) > 0) {
//                    MD5_Update(&md5Ctx, buffer, bytesRead);
                    env->CallVoidMethod(messageDigestObj,md5update,convertByteArrayToJByteArray(env,buffer,bytesRead));
                }
                env->ReleaseByteArrayElements(bufferObj, buffer, 0);
                env->DeleteLocalRef(bufferObj);

                // 关闭InputStream对象
                env->CallVoidMethod(inputObj, closeMethod);
                env->DeleteLocalRef(inputObj);
            }

            env->ReleaseStringUTFChars(nameObj, entryName);
            env->DeleteLocalRef(nameObj);
            env->DeleteLocalRef(zipEntryObj);
        }

        hasMoreElements = env->CallBooleanMethod(entriesObj, hasMoreElementsMethod);
    }

    // 释放资源
    env->DeleteLocalRef(entriesObj);
    env->DeleteLocalRef(zipFileObj);
    env->ReleaseStringUTFChars(apk_path, apkPath);

    jbyteArray jbyteArray1 = static_cast<jbyteArray>(env->CallObjectMethod(messageDigestObj,
                                                                           md5digest));
    jsize jsize1 = env->GetArrayLength(jbyteArray1) ;

    jbyte* jbyte1= env->GetByteArrayElements(jbyteArray1,0);

    char buf[33];
    for (int i=0;i<jsize1;i++) {
        sprintf(buf + i * 2,"%02X",jbyte1[i]);
    }
    buf[32] = 0;
    LOGE("%s",buf);

    return env->NewStringUTF(buf);

}