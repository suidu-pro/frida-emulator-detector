// frida_emulator_detect_monitor.js
// 用途：监控 App 检测模拟器时调用的 API，输出检测点及调用栈
// 使用：frida -U -f <包名> -l frida_emulator_detect_monitor.js --no-pause

'use strict';

// ─── 工具函数 ───────────────────────────────────────────────────────────────

function tag(category) {
    return `\x1b[36m[${category}]\x1b[0m`;
}

function logHit(category, method, value, showStack) {
    console.log(`\n${tag(category)} ${method}`);
    if (value !== undefined && value !== null) {
        console.log(`  \x1b[33m返回值/参数:\x1b[0m ${value}`);
    }
    if (showStack) {
        console.log(`  \x1b[90m调用栈:\x1b[0m\n  ${Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join('\n  ')}`);
    }
}

const SHOW_STACK = false; // 改为 true 可输出完整调用栈（性能较慢）

// ─── 1. 系统属性检测（ro.product.*, ro.hardware 等）────────────────────────

function hookSystemProperties() {
    const EMULATOR_PROPS = [
        'ro.product.model', 'ro.product.brand', 'ro.product.name',
        'ro.product.manufacturer', 'ro.product.device', 'ro.product.board',
        'ro.hardware', 'ro.kernel.qemu', 'ro.kernel.qemu.gles',
        'ro.build.fingerprint', 'ro.build.product',
        'init.svc.qemu-props', 'qemu.hw.mainkeys',
        'ro.bootloader', 'ro.boot.hardware',
    ];

    const SystemProperties = Java.use('android.os.SystemProperties');

    try {
        SystemProperties.get.overload('java.lang.String').implementation = function (key) {
            const result = this.get(key);
            if (EMULATOR_PROPS.includes(key) || key.includes('qemu') || key.includes('emu')) {
                logHit('SystemProperties', `get("${key}")`, result, SHOW_STACK);
            }
            return result;
        };
    } catch (e) {}

    try {
        SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function (key, def) {
            const result = this.get(key, def);
            if (EMULATOR_PROPS.includes(key) || key.includes('qemu') || key.includes('emu')) {
                logHit('SystemProperties', `get("${key}", "${def}")`, result, SHOW_STACK);
            }
            return result;
        };
    } catch (e) {}
}

// ─── 2. Build 字段读取 ─────────────────────────────────────────────────────

function hookBuildFields() {
    const Build = Java.use('android.os.Build');
    const FIELDS = ['FINGERPRINT', 'MODEL', 'MANUFACTURER', 'BRAND',
                    'DEVICE', 'PRODUCT', 'HARDWARE', 'BOARD', 'HOST',
                    'TAGS', 'USER'];

    FIELDS.forEach(field => {
        try {
            const f = Build.class.getDeclaredField(field);
            f.setAccessible(true);
            const val = f.get(null);
            console.log(`${tag('Build.Fields')} ${field} = ${val}`);
        } catch (e) {}
    });
}

// ─── 3. 文件路径检测 ───────────────────────────────────────────────────────

function hookFileDetection() {
    const EMULATOR_PATHS = [
        '/dev/socket/qemud', '/dev/qemu_pipe',
        '/system/lib/libc_malloc_debug_qemu.so',
        '/sys/qemu_trace', '/system/bin/qemu-props',
        '/dev/socket/baseband_at', '/system/bin/androVM-prop',
        '/system/xbin/nodaemon', '/system/bin/microvirt-prop',
        '/system/bin/ttVM_x86',
        '/data/data/com.bluestacks', '/data/data/com.microvirt',
    ];

    const File = Java.use('java.io.File');

    // hook exists()：稳定，所有 Android 版本均可用
    try {
        File.exists.implementation = function () {
            const path = this.getAbsolutePath();
            const result = this.exists();
            if (EMULATOR_PATHS.some(p => path.includes(p)) ||
                path.includes('qemu') || path.includes('emu') || path.includes('geny')) {
                logHit('File.exists', `"${path}"`, result, SHOW_STACK);
            }
            return result;
        };
    } catch (e) {
        console.warn('[File.exists] hook 失败:', e.message);
    }

    // hook isFile() / isDirectory()：作为 exists() 的补充检测点
    ['isFile', 'isDirectory'].forEach(method => {
        try {
            File[method].implementation = function () {
                const path = this.getAbsolutePath();
                const result = this[method]();
                if (EMULATOR_PATHS.some(p => path.includes(p)) ||
                    path.includes('qemu') || path.includes('emu') || path.includes('geny')) {
                    logHit(`File.${method}`, `"${path}"`, result, SHOW_STACK);
                }
                return result;
            };
        } catch (e) {}
    });

    // 注意：java.io.File 构造器（$init）在部分 Android 版本中为 native 实现，
    // 直接 hook 会触发 "invalid address" 错误，此处改用 Native 层拦截 open/access 系统调用。
    try {
        const libc = Process.getModuleByName('libc.so');
        for (const sym of ['access', 'open', 'open64', 'fopen']) {
            const fn = libc.findExportByName(sym);
            if (!fn) continue;
            Interceptor.attach(fn, {
                onEnter(args) {
                    try {
                        const path = args[0].readCString();
                        if (path && (EMULATOR_PATHS.some(p => path.includes(p)) ||
                            path.includes('qemu') || path.includes('geny') || path.includes('bluestacks'))) {
                            console.log(`\n${'\x1b[36m'}[Native.${sym}]\x1b[0m "${path}"`);
                        }
                    } catch (e) {}
                }
            });
        }
    } catch (e) {
        console.warn('[Native file hook] 失败:', e.message);
    }
}

// ─── 4. 传感器检测（模拟器通常无传感器）─────────────────────────────────

function hookSensorDetection() {
    const SensorManager = Java.use('android.hardware.SensorManager');

    try {
        SensorManager.getDefaultSensor.overload('int').implementation = function (type) {
            const sensor = this.getDefaultSensor(type);
            if (sensor === null) {
                logHit('SensorManager', `getDefaultSensor(type=${type}) → null (可能触发模拟器判断)`, null, SHOW_STACK);
            }
            return sensor;
        };
    } catch (e) {}

    try {
        SensorManager.getSensorList.overload('int').implementation = function (type) {
            const list = this.getSensorList(type);
            logHit('SensorManager', `getSensorList(${type}) → size=${list.size()}`, list.size(), SHOW_STACK);
            return list;
        };
    } catch (e) {}
}

// ─── 5. 网络 & 电话检测 ───────────────────────────────────────────────────

function hookTelephony() {
    try {
        const TelephonyManager = Java.use('android.telephony.TelephonyManager');

        ['getDeviceId', 'getImei', 'getMeid', 'getLine1Number',
         'getNetworkOperatorName', 'getNetworkCountryIso',
         'getSimOperator', 'getSimSerialNumber', 'getPhoneType'].forEach(method => {
            try {
                TelephonyManager[method].overload().implementation = function () {
                    const result = this[method]();
                    logHit('TelephonyManager', `${method}()`, result, SHOW_STACK);
                    return result;
                };
            } catch (e) {}
        });
    } catch (e) {}
}

// ─── 6. CPU & ABI 检测 ────────────────────────────────────────────────────

function hookCpuAbi() {
    const Build = Java.use('android.os.Build');
    try {
        const abiField = Build.class.getDeclaredField('CPU_ABI');
        abiField.setAccessible(true);
        console.log(`${tag('Build.CPU_ABI')} CPU_ABI = ${abiField.get(null)}`);
    } catch (e) {}

    try {
        const abisField = Build.class.getDeclaredField('SUPPORTED_ABIS');
        abisField.setAccessible(true);
        const abis = Java.array('java.lang.String', abisField.get(null));
        console.log(`${tag('Build.SUPPORTED_ABIS')} ${JSON.stringify(abis)}`);
    } catch (e) {}
}

// ─── 7. 进程/包名检测（检测已知模拟器包） ────────────────────────────────

function hookPackageManager() {
    const EMULATOR_PKGS = [
        'com.bluestacks', 'com.bignox', 'com.microvirt', 'com.tencent.gamehelper',
        'com.kaopu.kp', 'com.androVM', 'com.genymotion', 'com.zhuoyi.market',
        'com.google.android.launcher.layouts.genymotion',
    ];

    try {
        const PackageManager = Java.use('android.app.ApplicationPackageManager');
        PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkgName, flags) {
            if (EMULATOR_PKGS.some(p => pkgName.includes(p))) {
                logHit('PackageManager', `getPackageInfo("${pkgName}")`, undefined, SHOW_STACK);
            }
            return this.getPackageInfo(pkgName, flags);
        };
    } catch (e) {}
}

// ─── 8. /proc/cpuinfo & /proc/self/maps 读取 ──────────────────────────────

function hookProcFiles() {
    const FileInputStream = Java.use('java.io.FileInputStream');
    const FileReader = Java.use('java.io.FileReader');
    const PROC_TARGETS = ['/proc/cpuinfo', '/proc/self/maps', '/proc/self/status',
                          '/sys/class/power_supply', '/proc/net/tcp'];

    FileInputStream.$init.overload('java.lang.String').implementation = function (path) {
        if (PROC_TARGETS.some(p => path && path.startsWith(p))) {
            logHit('FileInputStream', `open("${path}")`, undefined, SHOW_STACK);
        }
        this.$init(path);
    };

    FileReader.$init.overload('java.lang.String').implementation = function (path) {
        if (PROC_TARGETS.some(p => path && path.startsWith(p))) {
            logHit('FileReader', `open("${path}")`, undefined, SHOW_STACK);
        }
        this.$init(path);
    };
}

// ─── 9. 运行时命令执行（执行 shell 命令获取信息）─────────────────────────

function hookRuntime() {
    const Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
        logHit('Runtime.exec', `"${cmd}"`, undefined, SHOW_STACK);
        return this.exec(cmd);
    };
    try {
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmds) {
            logHit('Runtime.exec', JSON.stringify(cmds), undefined, SHOW_STACK);
            return this.exec(cmds);
        };
    } catch (e) {}
}

// ─── 10. Native 层：读取 qemu 相关属性（C 层）────────────────────────────

function hookNativeProperties() {
    try {
        const libc = Process.getModuleByName('libc.so');
        const __system_property_get = libc.getExportByName('__system_property_get');
        if (__system_property_get) {
            Interceptor.attach(__system_property_get, {
                onEnter(args) {
                    this.key = args[0].readCString();
                },
                onLeave(retval) {
                    if (this.key && (this.key.includes('qemu') || this.key.includes('emu') ||
                        this.key.includes('geny') || this.key.includes('bluestacks'))) {
                        console.log(`\n${tag('Native __system_property_get')} key="${this.key}"`);
                    }
                }
            });
        }
    } catch (e) {
        console.warn('[Native] 无法 hook __system_property_get:', e.message);
    }
}

// ─── 入口 ─────────────────────────────────────────────────────────────────

console.log('\x1b[32m[*] 模拟器检测监控脚本已加载，等待 Java 环境...\x1b[0m');

Java.perform(() => {
    console.log('\x1b[32m[*] Java 环境就绪，开始 Hook\x1b[0m\n');

    hookSystemProperties();
    hookBuildFields();
    hookFileDetection();
    hookSensorDetection();
    hookTelephony();
    hookCpuAbi();
    hookPackageManager();
    hookProcFiles();
    hookRuntime();

    console.log('\x1b[32m[*] Java 层 Hook 完成\x1b[0m');
});

// Native hook 在 Java.perform 外执行
hookNativeProperties();
