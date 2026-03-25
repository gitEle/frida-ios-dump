# frida-ios-dump
Pull a decrypted IPA from a jailbroken device


## Usage

 1. Install [frida](http://www.frida.re/) on device
 2. `sudo pip install -r requirements.txt --upgrade`
 3. Run usbmuxd/iproxy SSH forwarding over USB (Default 2222 -> 22). e.g. `iproxy 2222 22`
 4. Run ./dump.py `Display name` or `Bundle identifier`

For SSH/SCP make sure you have your public key added to the target device's ~/.ssh/authorized_keys file.

```
./dump.py Aftenposten
Start the target app Aftenposten
Dumping Aftenposten to /var/folders/wn/9v1hs8ds6nv_xj7g95zxyl140000gn/T
start dump /var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/AftenpostenApp
start dump /private/var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/Frameworks/AFNetworking.framework/AFNetworking
start dump /private/var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/Frameworks/ATInternet_iOS_ObjC_SDK.framework/ATInternet_iOS_ObjC_SDK
start dump /private/var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/Frameworks/SPTEventCollector.framework/SPTEventCollector
start dump /private/var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/Frameworks/SPiDSDK.framework/SPiDSDK
start dump /private/var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/Frameworks/libswiftCore.dylib
start dump /private/var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/Frameworks/libswiftCoreData.dylib
start dump /private/var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/Frameworks/libswiftCoreGraphics.dylib
start dump /private/var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/Frameworks/libswiftCoreImage.dylib
start dump /private/var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/Frameworks/libswiftCoreLocation.dylib
start dump /private/var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/Frameworks/libswiftDarwin.dylib
start dump /private/var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/Frameworks/libswiftDispatch.dylib
start dump /private/var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/Frameworks/libswiftFoundation.dylib
start dump /private/var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/Frameworks/libswiftObjectiveC.dylib
start dump /private/var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/Frameworks/libswiftQuartzCore.dylib
start dump /private/var/containers/Bundle/Application/66423A80-0AFE-471C-BC9B-B571107D3C27/AftenpostenApp.app/Frameworks/libswiftUIKit.dylib
Generating Aftenposten.ipa

Done.
```

Congratulations!!! You've got a decrypted IPA file.

Drag to [MonkeyDev](https://github.com/AloneMonkey/MonkeyDev), Happy hacking!

## Support

Python 2.x and 3.x


### issues

If the following error occurs:

* causes device to reboot
* lost connection
* unexpected error while probing dyld of target process

please open the application before dumping.



# dump.js 兼容性修复记录

适配 frida 16+ / 17+，原始代码基于 frida 12.x API 编写。

---

## 修改 1：移除 `Module.ensureInitialized`

**原因**：`Module.ensureInitialized()` 在 frida 16+ 中被删除。

```diff
- Module.ensureInitialized('Foundation');
+ // Module.ensureInitialized removed in frida 16+, Foundation is always loaded on iOS
```

---

## 修改 2：`Memory.read*/write*` 静态方法 → NativePointer 实例方法

**原因**：frida 14 已废弃、frida 16 正式删除所有 `Memory.readXxx(ptr)` / `Memory.writeXxx(ptr, val)` 形式的静态方法，改为在 NativePointer 实例上调用。

涉及函数：`putStr` / `getByteArr` / `getU8` / `putU8` / `getU16` / `putU16` / `getU32` / `putU32` / `getU64` / `putU64` / `getPt` / `putPt`

```diff
- return Memory.writeUtf8String(addr, str);
+ return addr.writeUtf8String(str);

- return Memory.readByteArray(addr, l);
+ return addr.readByteArray(l);

- return Memory.readU8(addr);
+ return addr.readU8();

- return Memory.writeU8(addr, n);
+ return addr.writeU8(n);

- return Memory.readU16(addr);
+ return addr.readU16();

- return Memory.writeU16(addr, n);
+ return addr.writeU16(n);

- return Memory.readU32(addr);
+ return addr.readU32();

- return Memory.writeU32(addr, n);
+ return addr.writeU32(n);

- return Memory.readU64(addr);
+ return addr.readU64();

- return Memory.writeU64(addr, n);
+ return addr.writeU64(n);

- return Memory.readPointer(addr);
+ return addr.readPointer();

- return Memory.writePointer(addr, n);
+ return addr.writePointer(n);
```

> `Memory.alloc()` / `Memory.allocUtf8String()` 仍保留在 `Memory` 上，无需修改。

---

## 修改 3：`Module.findExportByName(null, name)` → 遍历模块

**原因**：frida 16+ 的 `Module.findExportByName(null, name)`（第一参数为 null 搜全部模块）行为变化，在 QuickJS runtime 下不可用。改为手动遍历所有模块的实例方法。

新增兼容函数：

```javascript
function findExportByNameCompat(name) {
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
        var addr = mods[i].findExportByName(name);
        if (addr) return addr;
    }
    return null;
}
```

`getExportFunction` 内部改用此函数：

```diff
- nptr = Module.findExportByName(null, name);
+ nptr = findExportByNameCompat(name);
```

---

## 修改 4：`Process.enumerateModulesSync()` → `Process.enumerateModules()`

**原因**：frida 16+ 删除了所有带 `Sync` 后缀的同步枚举方法，现在 `enumerateModules()` 本身即同步返回。

```diff
- var tmpmods = Process.enumerateModulesSync();
+ var tmpmods = Process.enumerateModules();
```

---

## 修改 5：`getDocumentDir()` 移除 ObjC 依赖

**原因**：frida 16+ 的 QuickJS runtime 下 `ObjC` 不再是全局变量。

原实现通过 ObjC 调用 `NSSearchPathForDirectoriesInDomains` 返回的 NSArray。改为通过 `getenv("HOME")` 获取 app 容器 Home 目录，Documents 目录始终是 `$HOME/Documents`。

```diff
- function getDocumentDir() {
-     var NSDocumentDirectory = 9;
-     var NSUserDomainMask = 1;
-     var npdirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, 1);
-     return ObjC.Object(npdirs).objectAtIndex_(0).toString();
- }
+ function getDocumentDir() {
+     var getenvFn = new NativeFunction(findExportByNameCompat('getenv'), 'pointer', ['pointer']);
+     var homeDir = getenvFn(Memory.allocUtf8String('HOME')).readUtf8String();
+     return homeDir + '/Documents';
+ }
```

---

## 修改 6：`handleMessage` 中移除 `ObjC.classes.NSBundle`

**原因**：同上，`ObjC` 不可用。

原实现通过 `NSBundle.mainBundle().bundlePath()` 获取 `.app` 路径。改为从已加载模块的路径中截取 `.app` 目录路径。

```diff
- var app_path = ObjC.classes.NSBundle.mainBundle().bundlePath();
+ var app_path = '';
+ for (var mi = 0; mi < modules.length; mi++) {
+     var idx = modules[mi].path.indexOf('.app/');
+     if (idx !== -1) { app_path = modules[mi].path.substring(0, idx + 4); break; }
+ }
```

---

## 受影响的 frida 版本

| frida 版本 | 兼容性 |
|-----------|--------|
| < 14.x    | 原始代码可用 |
| 14.x – 15.x | `Memory.read*` 已废弃但仍可用（警告） |
| 16.x +    | 需要本文档全部修改 |
| 17.x      | 同上，已验证可用 |


