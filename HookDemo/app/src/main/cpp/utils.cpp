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



const char *app_sha1="99C6E6A24145D3F3E7F33D431A3665D6C906482E";
const char hexcode[] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

char* getSha1(JNIEnv *env, jobject context_object){
    //上下文对象
    jclass context_class = env->GetObjectClass(context_object);

    //反射获取PackageManager
    jmethodID methodId = env->GetMethodID(context_class, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jobject package_manager = env->CallObjectMethod(context_object, methodId);
    if (package_manager == NULL) {
        LOGD("package_manager is NULL!!!");
        return NULL;
    }

    jclass ContextWrapper_class = env->FindClass("android/content/ContextWrapper");

    //反射获取包名
    methodId = env->GetMethodID(ContextWrapper_class, "getPackageName", "()Ljava/lang/String;");
    jstring package_name = (jstring)env->CallObjectMethod(context_object, methodId);
    if (package_name == NULL) {
        LOGD("package_name is NULL!!!");
        return NULL;
    }
    env->DeleteLocalRef(context_class);

    //获取PackageInfo对象
    jclass pack_manager_class = env->GetObjectClass(package_manager);
    methodId = env->GetMethodID(pack_manager_class, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    env->DeleteLocalRef(pack_manager_class);
    jobject package_info = env->CallObjectMethod(package_manager, methodId, package_name, 0x40);
    if (package_info == NULL) {
        LOGD("getPackageInfo() is NULL!!!");
        return NULL;
    }
    env->DeleteLocalRef(package_manager);

    //获取签名信息
    jclass package_info_class = env->GetObjectClass(package_info);
    jfieldID fieldId = env->GetFieldID(package_info_class, "signatures", "[Landroid/content/pm/Signature;");
    env->DeleteLocalRef(package_info_class);
    jobjectArray signature_object_array = (jobjectArray)env->GetObjectField(package_info, fieldId);
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
    jclass byte_array_input_class=env->FindClass("java/io/ByteArrayInputStream");
    methodId=env->GetMethodID(byte_array_input_class,"<init>","([B)V");
    jobject byte_array_input=env->NewObject(byte_array_input_class,methodId,signature_byte);
    jclass certificate_factory_class=env->FindClass("java/security/cert/CertificateFactory");
    methodId=env->GetStaticMethodID(certificate_factory_class,"getInstance","(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;");
    jstring x_509_jstring=env->NewStringUTF("X.509");
    jobject cert_factory=env->CallStaticObjectMethod(certificate_factory_class,methodId,x_509_jstring);
    methodId=env->GetMethodID(certificate_factory_class,"generateCertificate",("(Ljava/io/InputStream;)Ljava/security/cert/Certificate;"));
    jobject x509_cert=env->CallObjectMethod(cert_factory,methodId,byte_array_input);
    env->DeleteLocalRef(certificate_factory_class);
    jclass x509_cert_class=env->GetObjectClass(x509_cert);
    methodId=env->GetMethodID(x509_cert_class,"getEncoded","()[B");
    jbyteArray cert_byte=(jbyteArray)env->CallObjectMethod(x509_cert,methodId);
    env->DeleteLocalRef(x509_cert_class);
    jclass message_digest_class=env->FindClass("java/security/MessageDigest");
    methodId=env->GetStaticMethodID(message_digest_class,"getInstance","(Ljava/lang/String;)Ljava/security/MessageDigest;");
    jstring sha1_jstring=env->NewStringUTF("SHA1");
    jobject sha1_digest=env->CallStaticObjectMethod(message_digest_class,methodId,sha1_jstring);
    methodId=env->GetMethodID(message_digest_class,"digest","([B)[B");
    jbyteArray sha1_byte=(jbyteArray)env->CallObjectMethod(sha1_digest,methodId,cert_byte);
    env->DeleteLocalRef(message_digest_class);

    //转换成char
    jsize array_size=env->GetArrayLength(sha1_byte);
    jbyte* sha1 =env->GetByteArrayElements(sha1_byte,NULL);
    char *hex_sha=new char[array_size*2+1];
    for (int i = 0; i <array_size ; ++i) {
        hex_sha[2*i]=hexcode[((unsigned char)sha1[i])/16];
        hex_sha[2*i+1]=hexcode[((unsigned char)sha1[i])%16];
    }
    hex_sha[array_size*2]='\0';

    LOGD("hex_sha %s ",hex_sha);
    return hex_sha;
}
jobject getGlobalContext(JNIEnv *env)
{
    //获取Activity Thread的实例对象
    jclass activityThread = env->FindClass("android/app/ActivityThread");

    jmethodID currentActivityThread = env->GetStaticMethodID(activityThread, "currentActivityThread", "()Landroid/app/ActivityThread;");
    jobject at = env->CallStaticObjectMethod(activityThread, currentActivityThread);
    //获取Application，也就是全局的Context
    jmethodID getApplication = env->GetMethodID(activityThread, "getApplication", "()Landroid/app/Application;");
    jobject context = env->CallObjectMethod(at, getApplication);
    return context;
}


jboolean checkValidity(JNIEnv *env,char *sha1){
    //比较签名
    if (strcmp(sha1,app_sha1)==0)
    {
        LOGD("验证成功");
        return true;
    }
    LOGD("验证失败");
    return false;
}



void formatSignature(char* data, char* resultData) {
    int resultIndex = 0;
    int length = strlen(data);
    for(int i = 0; i < length; i++) {
        resultData[resultIndex] = static_cast<char>(toupper(data[i]));
        if(i % 2 == 1 && i != length -1) {
            resultData[resultIndex+1] = ':';
            resultIndex+=2;
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
    if(ELFCLASS64 != ehdr->e_ident[EI_CLASS]) return 0;
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

    for (unsigned char &m : frida_rpc) {
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
                LOGI("start check frida loop 111 %d",(read_line(fd, buffer, BUFFER_LEN)));
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
        LOGI("start check frida loop fd3333%d",fd);

        close(fd);

    return nullptr;
}