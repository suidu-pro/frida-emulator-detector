// frida_emulator_bypass.js
// 用途：针对百变大侦探 (com.mszmapp.detective) 的模拟器检测绕过
// 检测点来源：frida_emulator_detect_monitor.js 采集日志
// 使用：frida -U -f com.mszmapp.detective -l frida_emulator_bypass.js --no-pause

'use strict';

// ─── 伪造的真实设备信息（Samsung Galaxy S22，与 APK 签名环境一致）──────────

const FAKE_DEVICE = {
    FINGERPRINT:    'samsung/r0q/r0q:12/SP1A.210812.016/S9260ZCS4CWC1:user/release-keys',
    MODEL:          'SM-S9260',
    MANUFACTURER:   'samsung',
    BRAND:          'samsung',
    DEVICE:         'r0q',
    PRODUCT:        'r0q',
    HARDWARE:       'qcom',
    BOARD:          'r0q',
    HOST:           'SWDD8024',
    TAGS:           'release-keys',
    USER:           'dpi',
    CPU_ABI:        'arm64-v8a',
    BOOTLOADER:     'r0q',
};

// ─── 1. 修复 Build 字段 ────────────────────────────────────────────────────

function bypassBuildFields() {
    const Build = Java.use('android.os.Build');

    const fieldMap = {
        FINGERPRINT:  FAKE_DEVICE.FINGERPRINT,
        MODEL:        FAKE_DEVICE.MODEL,
        MANUFACTURER: FAKE_DEVICE.MANUFACTURER,
        BRAND:        FAKE_DEVICE.BRAND,
        DEVICE:       FAKE_DEVICE.DEVICE,
        PRODUCT:      FAKE_DEVICE.PRODUCT,
        HARDWARE:     FAKE_DEVICE.HARDWARE,
        BOARD:        FAKE_DEVICE.BOARD,
        HOST:         FAKE_DEVICE.HOST,
        TAGS:         FAKE_DEVICE.TAGS,
        USER:         FAKE_DEVICE.USER,
        BOOTLOADER:   FAKE_DEVICE.BOOTLOADER,
    };

    Object.entries(fieldMap).forEach(([field, fakeVal]) => {
        try {
            const f = Build.class.getDeclaredField(field);
            f.setAccessible(true);
            f.set(null, fakeVal);
            console.log(`[Build] ${field} → ${fakeVal}`);
        } catch (e) {
            console.warn(`[Build] 修改 ${field} 失败: ${e.message}`);
        }
    });
}

// ─── 2. Java 层 SystemProperties 伪造 ─────────────────────────────────────

function bypassSystemProperties() {
    // ro.kernel.qemu = 1 是最直接的模拟器标志，必须返回 "0" 或空
    const FAKE_PROPS = {
        'ro.kernel.qemu':           '0',
        'ro.kernel.qemu.gles':      '0',
        'qemu.hw.mainkeys':         '',
        'init.svc.qemu-props':      '',
        'ro.hardware':              'qcom',
        'ro.product.model':         FAKE_DEVICE.MODEL,
        'ro.product.brand':         FAKE_DEVICE.BRAND,
        'ro.product.manufacturer':  FAKE_DEVICE.MANUFACTURER,
        'ro.product.device':        FAKE_DEVICE.DEVICE,
        'ro.product.name':          FAKE_DEVICE.PRODUCT,
        'ro.build.fingerprint':     FAKE_DEVICE.FINGERPRINT,
        'ro.build.tags':            'release-keys',
        'ro.build.type':            'user',
    };

    const SystemProperties = Java.use('android.os.SystemProperties');

    try {
        SystemProperties.get.overload('java.lang.String').implementation = function (key) {
            if (key in FAKE_PROPS) {
                console.log(`[SystemProperties] get("${key}") → "${FAKE_PROPS[key]}" (原始已拦截)`);
                return FAKE_PROPS[key];
            }
            return this.get(key);
        };
    } catch (e) {}

    try {
        SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function (key, def) {
            if (key in FAKE_PROPS) {
                console.log(`[SystemProperties] get("${key}", "${def}") → "${FAKE_PROPS[key]}" (原始已拦截)`);
                return FAKE_PROPS[key];
            }
            return this.get(key, def);
        };
    } catch (e) {}

    try {
        SystemProperties.getInt.overload('java.lang.String', 'int').implementation = function (key, def) {
            if (key in FAKE_PROPS) {
                const v = parseInt(FAKE_PROPS[key]) || 0;
                console.log(`[SystemProperties] getInt("${key}") → ${v}`);
                return v;
            }
            return this.getInt(key, def);
        };
    } catch (e) {}

    console.log('[SystemProperties] Java 层 hook 完成');
}

// ─── 3. Native 层 __system_property_get 伪造 ──────────────────────────────
// 日志显示 ro.kernel.qemu 被 Native 层高频读取，必须在 C 层同步拦截

function bypassNativeProperties() {
    const NATIVE_FAKE = {
        'ro.kernel.qemu':        '0',
        'ro.kernel.qemu.gles':   '0',
        'qemu.hw.mainkeys':      '',
        'ro.build.tags':         'release-keys',
        'ro.build.type':         'user',
        'ro.product.model':      FAKE_DEVICE.MODEL,
        'ro.product.brand':      FAKE_DEVICE.BRAND,
        'ro.build.fingerprint':  FAKE_DEVICE.FINGERPRINT,
    };

    try {
        const libc = Process.getModuleByName('libc.so');
        const fn = libc.getExportByName('__system_property_get');

        Interceptor.attach(fn, {
            onEnter(args) {
                this.keyPtr = args[0];
                this.valPtr = args[1];
                try { this.key = args[0].readCString(); } catch (e) { this.key = null; }
            },
            onLeave(retval) {
                if (!this.key || !(this.key in NATIVE_FAKE)) return;
                const fakeVal = NATIVE_FAKE[this.key];
                try {
                    this.valPtr.writeUtf8String(fakeVal);
                    retval.replace(fakeVal.length);
                    console.log(`[Native] __system_property_get("${this.key}") → "${fakeVal}"`);
                } catch (e) {}
            }
        });

        console.log('[Native] __system_property_get hook 完成');
    } catch (e) {
        console.warn('[Native] hook 失败:', e.message);
    }
}

// ─── 4. Build.VERSION 修复（部分 app 检查 SDK / RELEASE）─────────────────

function bypassBuildVersion() {
    try {
        const BuildVersion = Java.use('android.os.Build$VERSION');
        const vf = BuildVersion.class.getDeclaredField('RELEASE');
        vf.setAccessible(true);
        vf.set(null, '12');

        const sdkf = BuildVersion.class.getDeclaredField('SDK_INT');
        sdkf.setAccessible(true);
        sdkf.set(null, 31); // Android 12
        console.log('[Build.VERSION] RELEASE=12, SDK_INT=31');
    } catch (e) {}
}

// ─── 入口 ─────────────────────────────────────────────────────────────────

console.log('\x1b[32m[*] 模拟器绕过脚本已加载\x1b[0m');

// Native hook 需在 Java.perform 之前注册
bypassNativeProperties();

Java.perform(() => {
    console.log('\x1b[32m[*] Java 环境就绪，开始注入伪造值\x1b[0m\n');

    bypassBuildFields();
    bypassSystemProperties();
    bypassBuildVersion();

    console.log('\n\x1b[32m[*] 所有绕过注入完成\x1b[0m');
});
