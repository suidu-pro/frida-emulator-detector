// frida_emulator_bypass.js
// 用途：针对百变大侦探 (com.mszmapp.detective) 的全维度模拟器检测绕过
// 使用：frida -U -f com.mszmapp.detective -l frida_emulator_bypass.js --no-pause

'use strict';

// ─── 伪造的真实设备信息（Samsung Galaxy S22）──────────────────────────────

const FAKE = {
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
    SERIAL:         'RF8N30KVXYZ',
    IMEI:           '861536030196001',
    ANDROID_ID:     'a1b2c3d4e5f67890',
    MAC:            '02:00:00:44:55:66',
    LINE1:          '+8613800138000',
    SIM_SERIAL:     '89860318640220133897',
    SUBSCRIBER_ID:  '460010987654321',
    OPERATOR:       '46001',
    OPERATOR_NAME:  '中国联通',
    COUNTRY_ISO:    'cn',
};

// ─── 1. Build 字段伪造 ────────────────────────────────────────────────────

function bypassBuildFields() {
    const Build = Java.use('android.os.Build');
    const fields = {
        FINGERPRINT: FAKE.FINGERPRINT, MODEL: FAKE.MODEL,
        MANUFACTURER: FAKE.MANUFACTURER, BRAND: FAKE.BRAND,
        DEVICE: FAKE.DEVICE, PRODUCT: FAKE.PRODUCT,
        HARDWARE: FAKE.HARDWARE, BOARD: FAKE.BOARD,
        HOST: FAKE.HOST, TAGS: FAKE.TAGS, USER: FAKE.USER,
        BOOTLOADER: FAKE.BOOTLOADER, SERIAL: FAKE.SERIAL,
    };
    Object.entries(fields).forEach(([k, v]) => {
        try {
            const f = Build.class.getDeclaredField(k);
            f.setAccessible(true);
            f.set(null, v);
        } catch (e) {}
    });

    // Build.VERSION
    try {
        const V = Java.use('android.os.Build$VERSION');
        V.class.getDeclaredField('RELEASE').tap(f => { f.setAccessible(true); f.set(null, '12'); });
        V.class.getDeclaredField('SDK_INT').tap(f => { f.setAccessible(true); f.set(null, 31); });
    } catch (e) {}

    console.log('[+] Build 字段已伪造');
}

// ─── 2. SystemProperties（Java 层）──────────────────────────────────────

function bypassSystemProperties() {
    const PROPS = {
        'ro.kernel.qemu': '0', 'ro.kernel.qemu.gles': '0',
        'qemu.hw.mainkeys': '', 'init.svc.qemu-props': '',
        'ro.hardware': 'qcom', 'ro.boot.hardware': 'qcom',
        'ro.product.model': FAKE.MODEL, 'ro.product.brand': FAKE.BRAND,
        'ro.product.manufacturer': FAKE.MANUFACTURER,
        'ro.product.device': FAKE.DEVICE, 'ro.product.name': FAKE.PRODUCT,
        'ro.product.board': FAKE.BOARD,
        'ro.build.fingerprint': FAKE.FINGERPRINT,
        'ro.build.tags': 'release-keys', 'ro.build.type': 'user',
        'ro.serialno': FAKE.SERIAL, 'ro.boot.serialno': FAKE.SERIAL,
        'ro.bootimage.build.fingerprint': FAKE.FINGERPRINT,
        'gsm.version.baseband': 'G973FXXU9FVH1',
        'persist.sys.dalvik.vm.lib.2': 'libart.so',
    };

    const SP = Java.use('android.os.SystemProperties');
    try {
        SP.get.overload('java.lang.String').implementation = function (key) {
            return (key in PROPS) ? PROPS[key] : this.get(key);
        };
    } catch (e) {}
    try {
        SP.get.overload('java.lang.String', 'java.lang.String').implementation = function (key, def) {
            return (key in PROPS) ? PROPS[key] : this.get(key, def);
        };
    } catch (e) {}
    try {
        SP.getInt.overload('java.lang.String', 'int').implementation = function (key, def) {
            return (key in PROPS) ? (parseInt(PROPS[key]) || 0) : this.getInt(key, def);
        };
    } catch (e) {}
    try {
        SP.getBoolean.overload('java.lang.String', 'boolean').implementation = function (key, def) {
            return (key in PROPS) ? (PROPS[key] === '1' || PROPS[key] === 'true') : this.getBoolean(key, def);
        };
    } catch (e) {}

    console.log('[+] SystemProperties 已伪造');
}

// ─── 3. Native __system_property_get ─────────────────────────────────────

function bypassNativeProperties() {
    const NATIVE = {
        'ro.kernel.qemu': '0', 'ro.kernel.qemu.gles': '0',
        'qemu.hw.mainkeys': '', 'init.svc.qemu-props': '',
        'ro.hardware': 'qcom', 'ro.boot.hardware': 'qcom',
        'ro.product.model': FAKE.MODEL, 'ro.product.brand': FAKE.BRAND,
        'ro.product.manufacturer': FAKE.MANUFACTURER,
        'ro.product.device': FAKE.DEVICE, 'ro.product.board': FAKE.BOARD,
        'ro.build.fingerprint': FAKE.FINGERPRINT,
        'ro.build.tags': 'release-keys', 'ro.build.type': 'user',
        'ro.serialno': FAKE.SERIAL, 'ro.boot.serialno': FAKE.SERIAL,
        'gsm.version.baseband': 'G973FXXU9FVH1',
    };

    try {
        const fn = Module.getExportByName('libc.so', '__system_property_get');
        Interceptor.attach(fn, {
            onEnter(args) {
                try { this.key = args[0].readCString(); } catch (e) { this.key = null; }
                this.valPtr = args[1];
            },
            onLeave(retval) {
                if (this.key && (this.key in NATIVE)) {
                    try {
                        this.valPtr.writeUtf8String(NATIVE[this.key]);
                        retval.replace(NATIVE[this.key].length);
                    } catch (e) {}
                }
            }
        });
        console.log('[+] Native __system_property_get 已 hook');
    } catch (e) {}
}

// ─── 4. 特征文件存在性检测 ──────────────────────────────────────────────

function bypassFileDetection() {
    const EMU_FILES = [
        '/dev/socket/qemud', '/dev/qemu_pipe', '/dev/goldfish_pipe',
        '/sys/qemu_trace', '/system/bin/qemu-props', '/system/bin/qemud',
        '/system/lib/libc_malloc_debug_qemu.so',
        '/system/bin/androVM-prop', '/system/bin/microvirt-prop',
        '/system/bin/nox-prop', '/system/bin/ttVM_x86',
        '/system/bin/droid4x-prop', '/system/bin/duos-prop',
        '/system/xbin/nodaemon',
        'ueventd.android_x86.rc', 'x86.prop', 'ueventd.ttVM_x86.rc',
        'fstab.andy', 'fstab.nox', 'fstab.vbox', 'init.vbox86.rc',
        'init.svc.qemu-props', 'init.goldfish.rc', 'init.ranchu.rc',
        '/dev/socket/genyd', '/dev/socket/baseband_at',
    ];

    const File = Java.use('java.io.File');

    try {
        File.exists.implementation = function () {
            const path = this.getAbsolutePath();
            if (EMU_FILES.some(p => path.includes(p))) {
                console.log(`[File.exists] 拦截 "${path}" → false`);
                return false;
            }
            return this.exists();
        };
    } catch (e) {}

    ['isFile', 'isDirectory', 'canRead'].forEach(m => {
        try {
            File[m].implementation = function () {
                const path = this.getAbsolutePath();
                if (EMU_FILES.some(p => path.includes(p))) return false;
                return this[m]();
            };
        } catch (e) {}
    });

    console.log('[+] 文件存在性检测已伪造');
}

// ─── 5. 电话/SIM/IMEI 伪造 ──────────────────────────────────────────────

function bypassTelephony() {
    try {
        const TM = Java.use('android.telephony.TelephonyManager');

        const hooks = {
            getDeviceId: FAKE.IMEI,
            getImei: FAKE.IMEI,
            getMeid: FAKE.IMEI,
            getLine1Number: FAKE.LINE1,
            getSimSerialNumber: FAKE.SIM_SERIAL,
            getSubscriberId: FAKE.SUBSCRIBER_ID,
            getSimOperator: FAKE.OPERATOR,
            getSimOperatorName: FAKE.OPERATOR_NAME,
            getNetworkOperator: FAKE.OPERATOR,
            getNetworkOperatorName: FAKE.OPERATOR_NAME,
            getNetworkCountryIso: FAKE.COUNTRY_ISO,
            getSimCountryIso: FAKE.COUNTRY_ISO,
        };

        Object.entries(hooks).forEach(([method, val]) => {
            // 无参版本
            try {
                TM[method].overload().implementation = function () { return val; };
            } catch (e) {}
            // int 参版本 (slotIndex)
            try {
                TM[method].overload('int').implementation = function () { return val; };
            } catch (e) {}
        });

        // getPhoneType → GSM
        try { TM.getPhoneType.overload().implementation = function () { return 1; }; } catch (e) {}
        // getNetworkType → LTE
        try { TM.getNetworkType.overload().implementation = function () { return 13; }; } catch (e) {}
        // getSimState → READY
        try { TM.getSimState.overload().implementation = function () { return 5; }; } catch (e) {}

        console.log('[+] TelephonyManager 已伪造');
    } catch (e) {}
}

// ─── 6. Settings.Secure.getString (ANDROID_ID 等) ────────────────────────

function bypassSettings() {
    try {
        const Secure = Java.use('android.provider.Settings$Secure');
        Secure.getString.implementation = function (resolver, name) {
            if (name === 'android_id') return FAKE.ANDROID_ID;
            return this.getString(resolver, name);
        };
        console.log('[+] Settings.Secure 已伪造');
    } catch (e) {}
}

// ─── 7. WiFi / 网络信息伪造 ─────────────────────────────────────────────

function bypassNetwork() {
    // WifiInfo MAC
    try {
        const WifiInfo = Java.use('android.net.wifi.WifiInfo');
        WifiInfo.getMacAddress.implementation = function () { return FAKE.MAC; };
        console.log('[+] WifiInfo MAC 已伪造');
    } catch (e) {}

    // NetworkInterface 过滤 eth0（模拟器虚拟网卡）
    try {
        const NI = Java.use('java.net.NetworkInterface');
        NI.getHardwareAddress.implementation = function () {
            const name = this.getName();
            if (name && (name === 'eth0' || name.includes('vbox') || name.includes('vnic'))) {
                // 返回真实 MAC 字节
                return [0x02, 0x00, 0x00, 0x44, 0x55, 0x66];
            }
            return this.getHardwareAddress();
        };
    } catch (e) {}
}

// ─── 8. 传感器检测绕过 ──────────────────────────────────────────────────

function bypassSensors() {
    // 模拟器通常传感器为空，部分 app 会检查
    // 无法伪造传感器对象本身，但可以确保 getSensorList 至少不返回空列表
    // 这一项在多数模拟器上不需额外处理（已有虚拟传感器）
    console.log('[+] 传感器检测：依赖模拟器内置虚拟传感器');
}

// ─── 9. /proc/cpuinfo 伪造（goldfish/ranchu → qcom）───────────────────

function bypassProcFiles() {
    try {
        const BR = Java.use('java.io.BufferedReader');
        BR.readLine.overload().implementation = function () {
            const line = this.readLine();
            if (line === null) return null;
            // 替换模拟器 CPU 特征
            return line
                .replace(/goldfish/gi, 'qcom')
                .replace(/ranchu/gi, 'qcom')
                .replace(/android sdk built for x86/gi, FAKE.MODEL)
                .replace(/generic/gi, 'qcom');
        };
        console.log('[+] /proc 文件读取已伪造');
    } catch (e) {}
}

// ─── 10. Runtime.exec 拦截（getprop / cat 命令）─────────────────────────

function bypassRuntimeExec() {
    const Runtime = Java.use('java.lang.Runtime');

    function wrapExec(process, cmd) {
        // 拦截 getprop ro.kernel.qemu / cat /proc/cpuinfo 等
        if (typeof cmd === 'string' &&
            (cmd.includes('getprop') || cmd.includes('/proc/cpuinfo') || cmd.includes('qemu'))) {
            console.log(`[Runtime.exec] 拦截: "${cmd}"`);
        }
        return process;
    }

    try {
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            return wrapExec(this.exec(cmd), cmd);
        };
    } catch (e) {}
    try {
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmds) {
            const joined = cmds.join(' ');
            return wrapExec(this.exec(cmds), joined);
        };
    } catch (e) {}

    console.log('[+] Runtime.exec 已监控');
}

// ─── 11. Native access() 拦截（仅限模拟器特征文件）──────────────────────

function bypassNativeAccess() {
    const EMU_PATHS_NATIVE = [
        'qemu_pipe', 'qemud', 'goldfish', 'qemu-props',
        'nox', 'vbox', 'geny', 'microvirt', 'androVM', 'ttVM',
    ];

    try {
        const accessFn = Module.getExportByName('libc.so', 'access');
        Interceptor.attach(accessFn, {
            onEnter(args) {
                try {
                    this.path = args[0].readCString();
                } catch (e) { this.path = null; }
            },
            onLeave(retval) {
                if (this.path && EMU_PATHS_NATIVE.some(p => this.path.includes(p))) {
                    retval.replace(-1); // 返回 -1 表示文件不存在
                    console.log(`[Native.access] 拦截 "${this.path}" → -1`);
                }
            }
        });
        console.log('[+] Native access() 已 hook');
    } catch (e) {}
}

// ─── 12. 蓝牙适配器（模拟器通常无蓝牙）────────────────────────────────

function bypassBluetooth() {
    try {
        const BA = Java.use('android.bluetooth.BluetoothAdapter');
        BA.getAddress.implementation = function () { return 'FC:1A:3E:7D:9B:42'; };
        BA.getName.implementation = function () { return FAKE.MODEL; };
        console.log('[+] BluetoothAdapter 已伪造');
    } catch (e) {}
}

// ─── 13. 电池检测（模拟器电池特征） ─────────────────────────────────────

function bypassBattery() {
    try {
        const Intent = Java.use('android.content.Intent');
        const origGetIntExtra = Intent.getIntExtra;
        Intent.getIntExtra.implementation = function (name, def) {
            // 伪造电池温度（模拟器温度=0）和电压
            if (name === 'temperature') return 280; // 28.0°C
            if (name === 'voltage') return 4200;
            return origGetIntExtra.call(this, name, def);
        };
        console.log('[+] 电池信息已伪造');
    } catch (e) {}
}

// ─── 入口 ─────────────────────────────────────────────────────────────────

console.log('\x1b[32m╔═══════════════════════════════════════════╗\x1b[0m');
console.log('\x1b[32m║  百变大侦探 - 模拟器检测全维度绕过 v2.0  ║\x1b[0m');
console.log('\x1b[32m╚═══════════════════════════════════════════╝\x1b[0m\n');

// Native hook 先于 Java
bypassNativeProperties();
bypassNativeAccess();

Java.perform(() => {
    bypassBuildFields();
    bypassSystemProperties();
    bypassFileDetection();
    bypassTelephony();
    bypassSettings();
    bypassNetwork();
    bypassSensors();
    bypassProcFiles();
    bypassRuntimeExec();
    bypassBluetooth();
    bypassBattery();

    console.log('\n\x1b[32m[*] 全部 13 项绕过注入完成，等待 App 行为...\x1b[0m\n');
});
