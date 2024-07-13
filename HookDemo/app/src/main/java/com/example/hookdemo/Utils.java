package com.example.hookdemo;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.Context;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.media.AudioManager;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.os.Build;
import android.os.Environment;
import android.os.StatFs;
import android.provider.Settings;
import android.text.TextUtils;
import android.util.Log;
import android.view.accessibility.AccessibilityManager;

public class Utils {
    private String TAG = "muyang";
    public boolean isWifiProxy(Context context) {
        final boolean IS_ICS_OR_LATER = Build.VERSION.SDK_INT >= Build.VERSION_CODES.ICE_CREAM_SANDWICH;
        String proxyAddress;
        int proxyPort;

        if (IS_ICS_OR_LATER) {
            proxyAddress = System.getProperty("http.proxyHost");
            String portStr = System.getProperty("http.proxyPort");
            proxyPort = Integer.parseInt((portStr != null ? portStr : "-1"));
        } else {
            proxyAddress = android.net.Proxy.getHost(context);
            proxyPort = android.net.Proxy.getPort(context);
        }
        return (!TextUtils.isEmpty(proxyAddress)) && (proxyPort != -1);
    }


    public boolean isVpnConnectionActive(Context context) {
        ConnectivityManager connectivityManager = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);

        if (connectivityManager != null) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                Network activeNetwork = connectivityManager.getActiveNetwork();
                if (activeNetwork != null) {
                    NetworkCapabilities capabilities = connectivityManager.getNetworkCapabilities(activeNetwork);
                    if (capabilities != null) {
                        return capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
                    }
                }
            } else {
                // For lower than Android M devices
                for (Network network : connectivityManager.getAllNetworks()) {
                    NetworkInfo networkInfo = connectivityManager.getNetworkInfo(network);
                    if (networkInfo != null && networkInfo.isConnectedOrConnecting()) {
                        return networkInfo.getType() == ConnectivityManager.TYPE_VPN;
                    }
                }
            }
        }

        return false;
    }


    //获取当前音量
    public int getMediaVolume(Context context) {
        AudioManager audioManager = (AudioManager) context.getSystemService(Context.AUDIO_SERVICE);
        if(audioManager != null) {
            return audioManager.getStreamVolume(AudioManager.STREAM_MUSIC);
        }
        return 0;
    }

    //获取当前屏幕亮度
    public int getScreenBrightness(Context context) {
        try {
            ContentResolver contentResolver = context.getContentResolver();
            int brightness = Settings.System.getInt(contentResolver, Settings.System.SCREEN_BRIGHTNESS);
            return brightness;
        } catch (Settings.SettingNotFoundException e) {
            Log.e(TAG, "Error getting screen brightness", e);
        }
        return -1;
    }

    //检查某个 无障碍服务 是否打开
    public boolean isAccessibilityServiceEnabled(Context context, String serviceName) {
        String enabledServicesSetting = Settings.Secure.getString(
                context.getContentResolver(),
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        );
        if (enabledServicesSetting != null) {
            TextUtils.SimpleStringSplitter colonSplitter = new TextUtils.SimpleStringSplitter(':');
            colonSplitter.setString(enabledServicesSetting);
            while (colonSplitter.hasNext()) {
                String componentNameString = colonSplitter.next();
                ComponentName enabledService = ComponentName.unflattenFromString(componentNameString);
                if (enabledService != null && enabledService.flattenToString().contains(serviceName)) {
                    return true;
                }
            }
        }
        return false;
    }


    //检查某个权限是否打开
    public  boolean hasPermission(Context context, String permission) {
        int permissionResult = context.checkCallingOrSelfPermission(permission);
        return permissionResult == PackageManager.PERMISSION_GRANTED;
    }


    //获取手机当前内存
    public  String getTotalStorageSizeInGB() {
        StatFs statFs = new StatFs(Environment.getDataDirectory().getPath());
        long blockSize = statFs.getBlockSizeLong();
        long totalBlocks = statFs.getBlockCountLong();
        long totalSizeBytes = totalBlocks * blockSize;
        double totalSizeGB = totalSizeBytes / (1024.0 * 1024.0 * 1024.0);
        return String.format("%.2fG", totalSizeGB);
    }


}

