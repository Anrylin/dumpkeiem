// Tweak.xm —— DumpKeiem
// 作用：在 ThemeBox / KeiEm 插件解密主题资源的那一刻，把【解密后的容器】和【key / iv】
//      直接写到 /var/mobile/Media/keiem_dump/，之后用 Filza 拿出来即可离线批量处理。
//
// 特点：
//   - 不依赖任何硬编码地址：运行时遍历所有 ObjC 类，按方法名找，只钩插件自己镜像里的类
//   - 直接钩 AES 包装方法（参数本身就是 key / iv）和两个解密结果加载方法
//   - 全程 @try/@catch，出错绝不影响微信
//
// 用法：装好后重启微信 → 在插件里【切到另一个主题】→ 去 Filza 拿文件

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dispatch/dispatch.h>
#import <stdlib.h>
#import <string.h>

#define kDir @"/var/mobile/Media/keiem_dump"
#define kLog @"/var/mobile/Media/keiem_dump/log.txt"

// ---------------- 工具 ----------------

static NSString *gWhy = nil;

static void EnsureDir(void) {
    [[NSFileManager defaultManager] createDirectoryAtPath:kDir
                              withIntermediateDirectories:YES
                                               attributes:nil error:nil];
}

static void LogLine(NSString *fmt, ...) {
    @try {
        va_list ap; va_start(ap, fmt);
        NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
        va_end(ap);
        NSString *line = [NSString stringWithFormat:@"[%@] %@\n",
                          [NSDate date], s];
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:kLog];
        if (!fh) {
            [line writeToFile:kLog atomically:YES encoding:NSUTF8StringEncoding error:nil];
        } else {
            [fh seekToEndOfFile];
            [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
            [fh closeFile];
        }
        NSLog(@"[DumpKeiem] %@", s);
    } @catch (NSException *e) { }
}

static NSString *HexOf(NSData *d, NSUInteger max) {
    if (!d || d.length == 0) return @"";
    NSUInteger n = MIN(d.length, max);
    const uint8_t *b = (const uint8_t *)d.bytes;
    NSMutableString *s = [NSMutableString stringWithCapacity:n * 2];
    for (NSUInteger i = 0; i < n; i++) [s appendFormat:@"%02x", b[i]];
    return s;
}

static NSString *Describe(id o, NSData **payloadOut) {
    if (!o || o == [NSNull null]) return @"nil";
    @try {
        if ([o isKindOfClass:[NSData class]]) {
            NSData *d = (NSData *)o;
            if (d.length > 4096 && payloadOut && !*payloadOut) *payloadOut = d;
            return [NSString stringWithFormat:@"NSData(%lu) hex=%@",
                    (unsigned long)d.length, HexOf(d, 48)];
        }
        if ([o isKindOfClass:[NSString class]]) {
            NSString *s = (NSString *)o;
            NSData *utf = [s dataUsingEncoding:NSUTF8StringEncoding];
            // 看起来像 16/24/32/64 字符的可打印串 -> 也当可疑密钥记下
            if (s.length >= 16 && s.length <= 128) return [NSString stringWithFormat:@"NSString(\"%s\")", s.UTF8String];
            return [NSString stringWithFormat:@"NSString(%lu) hex=%@",
                    (unsigned long)utf.length, HexOf(utf, 48)];
        }
        return [NSString stringWithFormat:@"<%@ %p>", NSStringFromClass([o class]), o];
    } @catch (NSException *e) { return @"<err>"; }
}

static NSString *Stamp(void) {
    static int n = 0;
    return [NSString stringWithFormat:@"%d_%d", (int)[[NSDate date] timeIntervalSince1970], n++];
}

static void DumpThing(NSString *where, NSArray *args) {
    @try {
        EnsureDir();
        NSMutableString *sum = [NSMutableString string];
        [sum appendFormat:@"\n==== %@ ====\n%@\n", where, [NSDate date]];
        NSData *payload = nil;
        NSMutableArray *maybeKey = [NSMutableArray array];

        for (NSUInteger i = 0; i < args.count; i++) {
            NSString *d = Describe(args[i], &payload);
            [sum appendFormat:@"  arg[%lu] %@\n", (unsigned long)i, d];
            id o = args[i];
            if ([o isKindOfClass:[NSString class]]) {
                NSString *s = (NSString *)o;
                if (s.length >= 16 && s.length <= 128 && ![s containsString:@" "])
                    [maybeKey addObject:s];
            } else if ([o isKindOfClass:[NSData class]] && [(NSData *)o length] == 16) {
                [maybeKey addObject:HexOf((NSData *)o, 16)];
            }
        }

        if (maybeKey.count) {
            [sum appendFormat:@"  >> 可疑密钥/IV: %@\n", [maybeKey componentsJoinedByString:@"  |  "]];
        }

        // 解密后的容器（大块 NSData）单独落盘 —— 这是离线处理的关键
        if (payload) {
            NSString *p = [kDir stringByAppendingPathComponent:
                           [NSString stringWithFormat:@"payload_%@_%lu.bin", Stamp(), (unsigned long)payload.length]];
            [payload writeToFile:p atomically:YES];
            [sum appendFormat:@"  >> 数据落盘: %@ (%lu B)\n", p, (unsigned long)payload.length];
        }

        // 追加到 log（同时保留最后一次到 key.txt，方便直接拿）
        NSString *cur = [NSString stringWithContentsOfFile:kLog encoding:NSUTF8StringEncoding error:nil] ?: @"";
        [[cur stringByAppendingString:sum] writeToFile:kLog atomically:YES
                                              encoding:NSUTF8StringEncoding error:nil];
        [sum writeToFile:[kDir stringByAppendingPathComponent:@"last.txt"] atomically:YES
                encoding:NSUTF8StringEncoding error:nil];
        NSLog(@"[DumpKeiem] %@", sum);
    } @catch (NSException *e) { }
}

// ---------------- 只钩插件镜像里的类 ----------------

static BOOL IsPluginClass(Class c) {
    const char *img = class_getImageName(c);
    if (!img) return NO;
    return strstr(img, "NewMessageRingUtil") != NULL;
}

typedef id (*IMP1)(id, SEL, id);
typedef id (*IMP2)(id, SEL, id, id);
typedef id (*IMP3)(id, SEL, id, id, id);
typedef id (*IMP4)(id, SEL, id, id, id, id);
typedef void (*IMPV1)(id, SEL, id);

// 已经钩过的实现，避免重复挂钩
static NSMutableSet *gHooked = nil;

static void EnsureHooked(void) {
    if (!gHooked) gHooked = [NSMutableSet set];
}

// 返回 void 的方法（loader 是 void，getter 是 id）—— 必须分开，否则 ARC 会误解返回值
static BOOL ReturnsVoid(SEL sel) {
    const char *n = sel_getName(sel);
    return strcmp(n, "loadIconMapFromDecryptedDat:") == 0 ||
           strcmp(n, "loadBubbleIconMapFromDecryptedDat:") == 0;
}

static BOOL HookSel(Class cls, SEL sel, int nargs) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return NO;
    IMP orig = method_getImplementation(m);
    if (!orig) return NO;
    NSString *key = [NSString stringWithFormat:@"%s|%p", sel_getName(sel), orig];
    if ([gHooked containsObject:key]) return NO;
    [gHooked addObject:key];

    SEL cs = sel;
    BOOL isVoid = ReturnsVoid(sel);
    @try {
        if (isVoid && nargs == 1) {
            IMP r = imp_implementationWithBlock(^void(id self, id a2) {
                DumpThing([NSString stringWithFormat:@"-[%@ %s]", NSStringFromClass([self class]), sel_getName(cs)], @[a2 ?: [NSNull null]]);
                ((IMPV1)orig)(self, cs, a2);
            });
            method_setImplementation(m, r);
            return YES;
        }
        switch (nargs) {
            case 1: {
                IMP r = imp_implementationWithBlock(^id(id self, id a2) {
                    DumpThing([NSString stringWithFormat:@"-[%@ %s]", NSStringFromClass([self class]), sel_getName(cs)], @[a2 ?: [NSNull null]]);
                    return ((IMP1)orig)(self, cs, a2);
                });
                method_setImplementation(m, r);
                break; }
            case 2: {
                IMP r = imp_implementationWithBlock(^id(id self, id a2, id a3) {
                    DumpThing([NSString stringWithFormat:@"-[%@ %s]", NSStringFromClass([self class]), sel_getName(cs)], @[a2 ?: [NSNull null], a3 ?: [NSNull null]]);
                    return ((IMP2)orig)(self, cs, a2, a3);
                });
                method_setImplementation(m, r);
                break; }
            case 3: {
                IMP r = imp_implementationWithBlock(^id(id self, id a2, id a3, id a4) {
                    DumpThing([NSString stringWithFormat:@"-[%@ %s]", NSStringFromClass([self class]), sel_getName(cs)], @[a2 ?: [NSNull null], a3 ?: [NSNull null], a4 ?: [NSNull null]]);
                    return ((IMP3)orig)(self, cs, a2, a3, a4);
                });
                method_setImplementation(m, r);
                break; }
            case 4: {
                IMP r = imp_implementationWithBlock(^id(id self, id a2, id a3, id a4, id a5) {
                    DumpThing([NSString stringWithFormat:@"-[%@ %s]", NSStringFromClass([self class]), sel_getName(cs)], @[a2 ?: [NSNull null], a3 ?: [NSNull null], a4 ?: [NSNull null], a5 ?: [NSNull null]]);
                    return ((IMP4)orig)(self, cs, a2, a3, a4, a5);
                });
                method_setImplementation(m, r);
                break; }
            default: return NO;
        }
    } @catch (NSException *e) { return NO; }
    return YES;
}

// 目标选择器 -> 参数个数
static NSDictionary<NSString *, NSNumber *> *Targets(void) {
    return @{
        // AES 包装（3 个参数：data, key, iv）
        @"aes256DecryptData:keyString:ivString:": @3,
        @"aes256EncryptData:keyString:ivString:": @3,
        @"aesDecryptData:keyString:iv:":          @3,
        @"aesEncryptData:keyString:iv:":          @3,
        @"aesDecryptString:keyString:iv:":        @3,
        @"aesEncryptString:keyString:iv:":        @3,
        // 4 个参数
        @"aesCrypt:data:keyString:ivString:":     @4,
        // 2 个参数
        @"hmacFromData:key:":                     @2,
        // ★ 解密结果加载（1 个参数：解密后的容器）—— 关键
        @"loadIconMapFromDecryptedDat:":          @1,
        @"loadBubbleIconMapFromDecryptedDat:":    @1,
        // 顺手（可能有原始文件名映射）
        @"getThemeColorXMLForOriginalPath:":      @1,
        @"getThemeColorCSSForOriginalPath:":      @1,
    };
}

// ==================== 授权绕过 ====================
// 这些是"检查/校验"类方法：强制返回成功，并记录调用（方便回头确认哪个才是真正的门）
// 0 = 参数个数未知，按探测到的类型走
static NSDictionary<NSString *, NSNumber *> *BypassReturns(void) {
    //  key: 选择器   value: 强制返回的值（对象，通常是 @YES / @1）
    return @{
        @"checkAuthabc":                          @YES,
        @"verifySign:canonical:derivedKey:":      @YES,
        @"verifyResponseSign:data:nonce:ts:sessionKey:": @YES,
        @"isExpired":                             @NO,
        @"validateFavoriteImageMessage:reason:":  @YES,
    };
}

// 只记录、不改返回值（用来"看"授权链路到底调了哪些东西）
static NSArray<NSString *> *WatchOnly(void) {
    return @[
        @"fetchAndSaveReceiptForTheme:",
        @"setPendingReceiptThemeID:",
        @"pendingReceiptThemeID",
        @"receiptSocket",
        @"setReceiptSocket:",
        @"importConfigFromDictionary:",
        @"keiEmImportBackupZip",
        @"java_setDisplayName:",
    ];
}

// ---------------- 强制返回 ----------------

typedef BOOL (*IMP_BOOL)(id, SEL, ...);

static void InstallBypass(void) {
    NSDictionary *bp = BypassReturns();
    int done = 0;
    int clsCount = objc_getClassList(NULL, 0);
    if (clsCount <= 0) return;
    Class *list = (Class *)malloc(sizeof(Class) * clsCount);
    objc_getClassList(list, clsCount);
    for (int i = 0; i < clsCount; i++) {
        Class c = list[i];
        if (!IsPluginClass(c)) continue;
        for (NSString *s in bp) {
            SEL sel = NSSelectorFromString(s);
            Method m = class_getInstanceMethod(c, sel);
            if (!m) continue;
            IMP orig = method_getImplementation(m);
            NSString *key = [NSString stringWithFormat:@"BP:%s|%p", sel_getName(sel), orig];
            if ([gHooked containsObject:key]) continue;
            [gHooked addObject:key];

            id forced = bp[s];
            SEL cs = sel;
            // 固定 4 参数签名：多余的参数被忽略，少参数时也多读无害（不取用）
            IMP r = imp_implementationWithBlock(^id(id self, id a2, id a3, id a4) {
                (void)a2; (void)a3; (void)a4;
                BOOL val = [forced boolValue];
                LogLine(@"★ 授权绕过命中: -[%@ %@] 强制返回 %@",
                        NSStringFromClass([self class]), NSStringFromSelector(cs),
                        val ? @"YES" : @"NO");
                return forced;
            });
            method_setImplementation(m, r);
            done++;
            LogLine(@"bypass 挂钩 -[%@ %@]", NSStringFromClass(c), s);
        }
    }
    free(list);
    LogLine(@"授权绕过：挂了 %d 个方法", done);
}

// ---------------- 只记录 ----------------

static void InstallWatch(void) {
    NSArray *wl = WatchOnly();
    int done = 0;
    int clsCount = objc_getClassList(NULL, 0);
    if (clsCount <= 0) return;
    Class *list = (Class *)malloc(sizeof(Class) * clsCount);
    objc_getClassList(list, clsCount);
    for (int i = 0; i < clsCount; i++) {
        Class c = list[i];
        if (!IsPluginClass(c)) continue;
        for (NSString *s in wl) {
            SEL sel = NSSelectorFromString(s);
            Method m = class_getInstanceMethod(c, sel);
            if (!m) continue;
            IMP orig = method_getImplementation(m);
            NSString *key = [NSString stringWithFormat:@"WO:%s|%p", sel_getName(sel), orig];
            if ([gHooked containsObject:key]) continue;
            [gHooked addObject:key];
            SEL cs = sel;
            // 统一按「最多 3 个参数」包装：多余的寄存器参数不影响
            IMP r = imp_implementationWithBlock(^id(id self, id a2, id a3, id a4) {
                DumpThing([NSString stringWithFormat:@"WATCH -[%@ %@]",
                           NSStringFromClass([self class]), NSStringFromSelector(cs)],
                          @[a2 ?: [NSNull null], a3 ?: [NSNull null], a4 ?: [NSNull null]]);
                return ((IMP3)orig)(self, cs, a2, a3, a4);
            });
            method_setImplementation(m, r);
            done++;
        }
    }
    free(list);
    LogLine(@"观察点：挂了 %d 个方法", done);
}

static void InstallHooks(void) {
    EnsureHooked();
    NSDictionary *tg = Targets();
    int clsCount = objc_getClassList(NULL, 0);
    if (clsCount <= 0) return;
    Class *list = (Class *)malloc(sizeof(Class) * clsCount);
    objc_getClassList(list, clsCount);

    int hooked = 0;
    for (int i = 0; i < clsCount; i++) {
        Class c = list[i];
        if (!IsPluginClass(c)) continue;
        for (NSString *s in tg) {
            if (HookSel(c, NSSelectorFromString(s), [tg[s] intValue])) {
                hooked++;
                LogLine(@"hook %@ -[%@ %@]", @"OK", NSStringFromClass(c), s);
            }
        }
    }
    free(list);
    LogLine(@"扫描 %d 个类，挂钩 %d 个方法，镜像=%@", clsCount, hooked, gWhy ?: @"NewMessageRingUtil");
}

__attribute__((constructor))
static void InitDump(void) {
    @autoreleasepool {
        EnsureDir();
        LogLine(@"DumpKeiem 启动，输出目录 %@", kDir);
        // 插件可能还没加载，稍后再扫
        for (NSNumber *delay in @[@0, @3, @8, @20, @40]) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                         (int64_t)([delay doubleValue] * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                @try {
                    InstallHooks();     // 抓取点
                    InstallBypass();    // 授权绕过
                    InstallWatch();     // 观察点
                } @catch (NSException *e) { LogLine(@"扫描异常: %@", e); }
            });
        }
    }
}
