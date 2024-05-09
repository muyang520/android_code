#include <jni.h>
#include<android/log.h>
#include <string>

#include <sys/types.h>
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <pthread.h>
#include <cstdlib>
#include <elf.h>
#include <link.h>
#include <fcntl.h>
#include <dirent.h>

#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>

#define TAG    "muyang" // 这个是自定义的LOG的标识
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,TAG,__VA_ARGS__) // 定义LOGD类型
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO,TAG,__VA_ARGS__) // 定义LOGI类型
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN,TAG,__VA_ARGS__) // 定义LOGW类型
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,TAG,__VA_ARGS__) // 定义LOGE类型

#define BUFFER_LEN 512

//extern "C" int wrap_openat(int, const char *, int, ...);
//
//extern "C" ssize_t wrap_read(int __fd, void *__buf, size_t __count);
//
//extern "C" int wrap_close(int __fd);
//
//extern "C" int wrap_kill(pid_t, int);



const char *app_sha1 = "99C6E6A24145D3F3E7F33D431A3665D6C906482E";
const char hexcode[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E',
                        'F'};

char *getSha1(JNIEnv *env, jobject context_object) {
    //上下文对象
    jclass context_class = env->GetObjectClass(context_object);

    //反射获取PackageManager
    jmethodID methodId = env->GetMethodID(context_class, "getPackageManager",
                                          "()Landroid/content/pm/PackageManager;");
    jobject package_manager = env->CallObjectMethod(context_object, methodId);
    if (package_manager == NULL) {
        LOGD("package_manager is NULL!!!");
        return NULL;
    }

    jclass ContextWrapper_class = env->FindClass("android/content/ContextWrapper");

    //反射获取包名
    methodId = env->GetMethodID(ContextWrapper_class, "getPackageName", "()Ljava/lang/String;");
    jstring package_name = (jstring) env->CallObjectMethod(context_object, methodId);
    if (package_name == NULL) {
        LOGD("package_name is NULL!!!");
        return NULL;
    }
    env->DeleteLocalRef(context_class);

    //获取PackageInfo对象
    jclass pack_manager_class = env->GetObjectClass(package_manager);
    methodId = env->GetMethodID(pack_manager_class, "getPackageInfo",
                                "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    env->DeleteLocalRef(pack_manager_class);
    jobject package_info = env->CallObjectMethod(package_manager, methodId, package_name, 0x40);
    if (package_info == NULL) {
        LOGD("getPackageInfo() is NULL!!!");
        return NULL;
    }
    env->DeleteLocalRef(package_manager);

    //获取签名信息
    jclass package_info_class = env->GetObjectClass(package_info);
    jfieldID fieldId = env->GetFieldID(package_info_class, "signatures",
                                       "[Landroid/content/pm/Signature;");
    env->DeleteLocalRef(package_info_class);
    jobjectArray signature_object_array = (jobjectArray) env->GetObjectField(package_info, fieldId);
    if (signature_object_array == NULL) {
        LOGD("signature is NULL!!!");
        return NULL;
    }
    jobject signature_object = env->GetObjectArrayElement(signature_object_array, 0);
    env->DeleteLocalRef(package_info);

    //签名信息转换成sha1值
    jclass signature_class = env->GetObjectClass(signature_object);
    methodId = env->GetMethodID(signature_class, "toByteArray", "()[B");
    env->DeleteLocalRef(signature_class);
    jbyteArray signature_byte = (jbyteArray) env->CallObjectMethod(signature_object, methodId);
    jclass byte_array_input_class = env->FindClass("java/io/ByteArrayInputStream");
    methodId = env->GetMethodID(byte_array_input_class, "<init>", "([B)V");
    jobject byte_array_input = env->NewObject(byte_array_input_class, methodId, signature_byte);
    jclass certificate_factory_class = env->FindClass("java/security/cert/CertificateFactory");
    methodId = env->GetStaticMethodID(certificate_factory_class, "getInstance",
                                      "(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;");
    jstring x_509_jstring = env->NewStringUTF("X.509");
    jobject cert_factory = env->CallStaticObjectMethod(certificate_factory_class, methodId,
                                                       x_509_jstring);
    methodId = env->GetMethodID(certificate_factory_class, "generateCertificate",
                                ("(Ljava/io/InputStream;)Ljava/security/cert/Certificate;"));
    jobject x509_cert = env->CallObjectMethod(cert_factory, methodId, byte_array_input);
    env->DeleteLocalRef(certificate_factory_class);
    jclass x509_cert_class = env->GetObjectClass(x509_cert);
    methodId = env->GetMethodID(x509_cert_class, "getEncoded", "()[B");
    jbyteArray cert_byte = (jbyteArray) env->CallObjectMethod(x509_cert, methodId);
    env->DeleteLocalRef(x509_cert_class);
    jclass message_digest_class = env->FindClass("java/security/MessageDigest");
    methodId = env->GetStaticMethodID(message_digest_class, "getInstance",
                                      "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    jstring sha1_jstring = env->NewStringUTF("SHA1");
    jobject sha1_digest = env->CallStaticObjectMethod(message_digest_class, methodId, sha1_jstring);
    methodId = env->GetMethodID(message_digest_class, "digest", "([B)[B");
    jbyteArray sha1_byte = (jbyteArray) env->CallObjectMethod(sha1_digest, methodId, cert_byte);
    env->DeleteLocalRef(message_digest_class);

    //转换成char
    jsize array_size = env->GetArrayLength(sha1_byte);
    jbyte *sha1 = env->GetByteArrayElements(sha1_byte, NULL);
    char *hex_sha = new char[array_size * 2 + 1];
    for (int i = 0; i < array_size; ++i) {
        hex_sha[2 * i] = hexcode[((unsigned char) sha1[i]) / 16];
        hex_sha[2 * i + 1] = hexcode[((unsigned char) sha1[i]) % 16];
    }
    hex_sha[array_size * 2] = '\0';

    LOGD("hex_sha %s ", hex_sha);
    return hex_sha;
}

jobject getGlobalContext(JNIEnv *env) {
    //获取Activity Thread的实例对象
    jclass activityThread = env->FindClass("android/app/ActivityThread");

    jmethodID currentActivityThread = env->GetStaticMethodID(activityThread,
                                                             "currentActivityThread",
                                                             "()Landroid/app/ActivityThread;");
    jobject at = env->CallStaticObjectMethod(activityThread, currentActivityThread);
    //获取Application，也就是全局的Context
    jmethodID getApplication = env->GetMethodID(activityThread, "getApplication",
                                                "()Landroid/app/Application;");
    jobject context = env->CallObjectMethod(at, getApplication);
    return context;
}


jboolean checkValidity(JNIEnv *env, char *sha1) {
    //比较签名
    if (strcmp(sha1, app_sha1) == 0) {
        LOGD("验证成功");
        return true;
    }
    LOGD("验证失败");
    return false;
}


void formatSignature(char *data, char *resultData) {
    int resultIndex = 0;
    int length = strlen(data);
    for (int i = 0; i < length; i++) {
        resultData[resultIndex] = static_cast<char>(toupper(data[i]));
        if (i % 2 == 1 && i != length - 1) {
            resultData[resultIndex + 1] = ':';
            resultIndex += 2;
        } else {
            resultIndex++;
        }
    }
}


int read_line(int fd, char *ptr, unsigned int maxlen) {
    int n;
    int rc;
    char c;

    for (n = 1; n < maxlen; n++) {
        if ((rc = read(fd, &c, 1)) == 1) {
            *ptr++ = c;
            if (c == '\n')
                break;
        } else if (rc == 0) {
            if (n == 1)
                return 0;    /* EOF no data read */
            else
                break;    /* EOF, some data read */
        } else
            return (-1);    /* error */
    }
    *ptr = 0;
    return (n);
}

int wrap_endsWith(const char *str, const char *suffix) {
    if (!str || !suffix)
        return 0;
    size_t lenA = strlen(str);
    size_t lenB = strlen(suffix);
    if (lenB > lenA)
        return 0;
    return strncmp(str + lenA - lenB, suffix, lenB) == 0;
}

int
wrap_memcmp(const unsigned char *s1, const unsigned char *s2, size_t n) {
    if (n != 0) {
        const unsigned char *p1 = s1;
        const unsigned char *p2 = s2;

        do {
            if (*p1++ != *p2++)
                return (*--p1 - *--p2);
        } while (--n != 0);
    }
    return (0);
}


int find_mem_string(long long base, long long end, unsigned char *ptr, unsigned int len) {

    unsigned char *rc = (unsigned char *) base;

    while ((long long) rc < end - len) {
        if (*rc == *ptr) {
            if (wrap_memcmp(rc, ptr, len) == 0) {
                return 1;
            }
        }

        rc++;

    }
    return 0;
}

int elf_check_header(uintptr_t base_addr) {
    ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *) base_addr;
    if (0 != memcmp(ehdr->e_ident, ELFMAG, SELFMAG)) return 0;
#if defined(__LP64__)
    if (ELFCLASS64 != ehdr->e_ident[EI_CLASS]) return 0;
#else
    if (ELFCLASS32 != ehdr->e_ident[EI_CLASS]) return 0;
#endif
    if (ELFDATA2LSB != ehdr->e_ident[EI_DATA]) return 0;
    if (EV_CURRENT != ehdr->e_ident[EI_VERSION]) return 0;
    if (ET_EXEC != ehdr->e_type && ET_DYN != ehdr->e_type) return 0;
    if (EV_CURRENT != ehdr->e_version) return 0;
    return 1;
}

void *check_loop(void *) {
    int fd;
    char path[256];
    char perm[5];
    unsigned long offset;
    unsigned int base;
    long end;
    char buffer[BUFFER_LEN];
    int loop = 0;
    unsigned int length = 11;
    //"frida:rpc"
    unsigned char frida_rpc[] =
            {

                    0xfe, 0xba, 0xfb, 0x4a, 0x9a, 0xca, 0x7f, 0xfb,
                    0xdb, 0xea, 0xfe, 0xdc
            };

    for (unsigned char &m: frida_rpc) {
        unsigned char c = m;
        c = ~c;
        c ^= 0xb1;
        c = (c >> 0x6) | (c << 0x2);
        c ^= 0x4a;
        c = (c >> 0x6) | (c << 0x2);
        m = c;
    }
    LOGI("start check frida loop");
    fd = openat(AT_FDCWD, "/proc/self/maps", O_RDONLY, 0);

    if (fd > 0) {

        while ((read_line(fd, buffer, BUFFER_LEN)) > 0) {
            if (sscanf(buffer, "%x-%lx %4s %lx %*s %*s %s", &base, &end, perm, &offset, path) !=
                5) {
                continue;
            }
            LOGI("start check frida loop 111 %d", (read_line(fd, buffer, BUFFER_LEN)));
            if (perm[0] != 'r') continue;
            if (perm[3] != 'p') continue; //do not touch the shared memory
            if (0 != offset) continue;
            if (strlen(path) == 0) continue;
            if ('[' == path[0]) continue;
            if (end - base <= 1000000) continue;
            if (wrap_endsWith(path, ".oat")) continue;
            if (elf_check_header(base) != 1) continue;
            if (find_mem_string(base, end, frida_rpc, length) == 1) {
                LOGI("frida found in memory!");
//#ifndef DEBUG
//                    kill(getpid(),SIGKILL);
//#endif
                break;
            }
        }
    } else {
        LOGI("open maps error");
    }
    LOGI("start check frida loop fd3333%d", fd);

    close(fd);

    return nullptr;
}


bool file_exist(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file != NULL) {
        fclose(file);
        return true;
    }
    return false;
}

//检测温度挂载文件：
int thermal_check() {
    DIR *dir_ptr;
    int count = 0;
    struct dirent *entry;
    if ((dir_ptr = opendir("/sys/class/thermal/")) != nullptr) {
        while ((entry = readdir(dir_ptr))) {
            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
                continue;
            }
            char *tmp = entry->d_name;
            if (strstr(tmp, "thermal_zone") != nullptr) {
                LOGD("找到的温度文件%s", tmp);
                count++;
            }
        }
        closedir(dir_ptr);
    } else {
        count = -1;
    }
    return count;
}

char *simulator_files_check() {
    if (file_exist("/system/bin/androVM-prop")) {//检测androidVM
        return "/system/bin/androVM-prop";
    } else if (file_exist("/system/bin/microvirt-prop")) {//检测逍遥模拟器--新版本找不到特征
        return "/system/bin/microvirt-prop";
    } else if (file_exist("/system/lib/libdroid4x.so")) {//检测海马模拟器
        return "/system/lib/libdroid4x.so";
    } else if (file_exist("/system/bin/windroyed")) {//检测文卓爷模拟器
        return "/system/bin/windroyed";
    } else if (file_exist("/system/bin/nox-prop")) {//检测夜神模拟器--某些版本找不到特征
        return "/system/bin/nox-prop";
    }
    LOGD("simulator file check info not find  ");
    return "";
}


// java中的jstring, 转化为c的一个字符数组
char *Jstring2CStr(JNIEnv *env, jstring jstr) {
    char *rtn = NULL;
    //获得java.lang.String类的一个实例
    jclass clsstring = (env)->FindClass("java/lang/String");
//指定编码方式
    jstring strencode = (env)->NewStringUTF("utf-8");//utf-16,GB2312
//获得方法 getBytes
    jmethodID mid = (env)->GetMethodID(clsstring, "getBytes", "(Ljava/lang/String;)[B");
//通过回调java中的getBytes方法将字符串jstr转换成uft-8编码的字节数组
    jbyteArray barr = (jbyteArray) (env)->CallObjectMethod(jstr, mid, strencode);
// String .getByte("GB2312");
//获得字节数组的长度
    jsize alen = (env)->GetArrayLength(barr);
//获得字节数组的首地址
    jbyte *ba = (env)->GetByteArrayElements(barr, JNI_FALSE);
    if (alen > 0) {
//分配内存空间
        rtn = (char *) malloc(alen + 1); //new char[alen+1]; "\0"
//将字符串ba复制到 rtn
        memcpy(rtn, ba, alen);
        rtn[alen] = 0;
    }
    (env)->ReleaseByteArrayElements(barr, ba, 0); //释放内存
    return rtn;
}

void main1_AAssetManager(JNIEnv *env,jobject thiz){

//    // Get the class of android.content.Context
//    jclass contextClass = env->FindClass("android/content/Context");
//
//    // Get the method ID of the method "getApplicationContext"
//    jmethodID getApplicationContextMethodId = env->GetMethodID(contextClass, "getApplicationContext", "()Landroid/content/Context;");
//
//    // Call the method on the object
//    jobject contextObject = env->CallObjectMethod(thiz, getApplicationContextMethodId);
//
//    // Get the method ID of the method "getAssets"
//    jmethodID getAssetsMethodId = env->GetMethodID(contextClass, "getAssets", "()Landroid/content/res/AssetManager;");
//
//    // Call the method on the context object
//    jobject assetManager = env->CallObjectMethod(contextObject, getAssetsMethodId);
    // 获取 Context 类
    jclass contextClass = env->FindClass("android/content/Context");

    // 获取 getAssets 方法的 MethodID
    jmethodID getAssets = env->GetMethodID(contextClass, "getAssets", "()Landroid/content/res/AssetManager;");

    // 调用 getAssets 方法获取 AssetManager 对象
    jobject assetManager = env->CallObjectMethod(getGlobalContext(env), getAssets);

    // 使用 assetManager 访问 APK 文件中的资源
    AAssetManager* mgr = AAssetManager_fromJava(env, assetManager);

    // Convert the AssetManager object to AAssetManager
    if (mgr == NULL) {
        LOGI("Failed to get AAssetManager.");
        return;
    }

    AAsset* asset = AAssetManager_open(mgr, "sample.txt", AASSET_MODE_BUFFER);
    if (asset == NULL) {
        LOGI("Failed to open sample.txt.");
        return;
    }

    off_t length = AAsset_getLength(asset);
    char* buffer = (char*) malloc(sizeof(char) * (length + 1));
    AAsset_read(asset, buffer, length);
    buffer[length] = '\0';

    LOGI("Asset content: %s", buffer);

    AAsset_close(asset);
    free(buffer);
}

bool areStringsEqual(JNIEnv *env, jobject thiz, jstring str1, jstring str2) {
    const char *nativeStr1 = env->GetStringUTFChars(str1, nullptr);
    const char *nativeStr2 = env->GetStringUTFChars(str2, nullptr);

    jboolean result = (strcmp(nativeStr1, nativeStr2) == 0) ? JNI_TRUE : JNI_FALSE;

    env->ReleaseStringUTFChars(str1, nativeStr1);
    env->ReleaseStringUTFChars(str2, nativeStr2);

    return result;
}