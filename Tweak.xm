// Tweak.xm —— DumpKeiem v8（精简版：只保留「确实работает」的那条路）
//
// 背景（一路排查得出的结论）：
//   · 插件解密 keiembox.dat 后，把结果放进 _themeMap 字典 —— 键就是【原始文件名】，值是解密后的 NSData；
//   · loadIconMapFromDecryptedDat: 接受【任意路径】，且插件自己负责解密；
//   · CCCrypt 不在插件的 bind 表里（多半是运行时 dlsym），所以「钩 C 函数拿密钥」那条路走不通。
//   ⇒ 结论：不需要密钥。让插件自己解密，我们只把 _themeMap 抄出来。
//   ⇒ 而且可以自动批量：遍历主题目录下所有 keiembox.dat，逐个调 loader，逐个抄。
//
// v8 相比 v7-v9 的改动：删掉整套 fishhook / CCCrypt 重绑定 / 槽写入 / AES 挂钩
//   （那些在真机上要么不命中、要么写只读页导致闪退）。现在完全不写任何内存。
//
// 输出目录：优先 /var/mobile/Media/keiem_dump，写不进去回退到 app 的 Documents/keiem_dump
//   <out>/KM/<主题名>/<原始文件名>    ← ★ 原版素材（这就是要的东西）
//   <out>/KM/_done.txt               ← 已处理主题清单（支持分批续跑）
//   <out>/icons/                     ← 顺手导出的原版 PNG
//   <out>/log.txt

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dispatch/dispatch.h>
#import <stdlib.h>
#import <string.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>

#define PLUGIN_HINT "NewMessageRingUtil"
#define kDirMedia  @"/var/mobile/Media/keiem_dump"

// ============================================================ 目录与日志

static NSString *gDir = nil, *gLog = nil;

static NSString *Dir(void) {
    if (gDir) return gDir;
    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *e = nil;
    if ([fm createDirectoryAtPath:kDirMedia withIntermediateDirectories:YES attributes:nil error:&e]) {
        NSString *t = [kDirMedia stringByAppendingPathComponent:@".w"];
        if ([@"x" writeToFile:t atomically:YES encoding:NSUTF8StringEncoding error:&e]) {
            [fm removeItemAtPath:t error:nil];
            gDir = kDirMedia;
        }
    }
    if (!gDir) {
        NSString *d = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/keiem_dump"];
        [fm createDirectoryAtPath:d withIntermediateDirectories:YES attributes:nil error:nil];
        gDir = d;
    }
    return gDir;
}

static NSString *LogPath(void) {
    if (!gLog) gLog = [Dir() stringByAppendingPathComponent:@"log.txt"];
    return gLog;
}

static void LogLine(NSString *fmt, ...) {
    @try {
        va_list ap; va_start(ap, fmt);
        NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
        va_end(ap);
        NSString *line = [NSString stringWithFormat:@"[%@] %@\n", [NSDate date], s];
        NSString *p = LogPath();
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:p];
        if (!fh) {
            [line writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil];
        } else {
            [fh seekToEndOfFile];
            [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
            [fh closeFile];
        }
        NSLog(@"[DumpKeiem] %@", s);
    } @catch (NSException *e) { }
}

// ============================================================ 只枚举插件镜像里的类

static NSArray<NSString *> *PluginClasses(void) {
    NSMutableArray *out = [NSMutableArray array];
    uint32_t nimg = _dyld_image_count();
    for (uint32_t i = 0; i < nimg; i++) {
        const char *path = _dyld_get_image_name(i);
        if (!path || !strstr(path, PLUGIN_HINT)) continue;
        unsigned int cnt = 0;
        const char **names = objc_copyClassNamesForImage(path, &cnt);
        if (!names) continue;
        for (unsigned int k = 0; k < cnt; k++)
            if (names[k]) [out addObject:[NSString stringWithUTF8String:names[k]]];
        free((void *)names);
    }
    return out;
}

static NSMutableSet *gSeen = nil;
static void EnsureSeen(void) { if (!gSeen) gSeen = [NSMutableSet set]; }

// ============================================================ 导出解密后的图像

static void DumpImageDict(NSDictionary *map, NSString *tag) {
    @try {
        if (![map isKindOfClass:[NSDictionary class]] || ![map count]) return;
        NSString *sub = [Dir() stringByAppendingPathComponent:@"icons"];
        [[NSFileManager defaultManager] createDirectoryAtPath:sub
                                  withIntermediateDirectories:YES attributes:nil error:nil];
        int n = 0;
        for (id k in map) {
            id v = map[k];
            if (![v isKindOfClass:[UIImage class]]) continue;
            NSData *png = UIImagePNGRepresentation((UIImage *)v);
            if (!png) continue;
            NSString *nm = [[k description] stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
            nm = [nm stringByReplacingOccurrencesOfString:@":" withString:@"_"];
            [png writeToFile:[sub stringByAppendingPathComponent:[nm stringByAppendingString:@".png"]]
                  atomically:YES];
            if (++n >= 5000) break;
        }
        if (n) LogLine(@"  >> 导出 %@ 图像 %d 张 -> icons/", tag, n);
    } @catch (NSException *e) { }
}

/// 把对象的 ivar 列出来（只列对象类型！非 @ 的当指针解引用会崩），大的 NSData 落盘
static void DumpIvars(id obj, const char *why) {
    @try {
        unsigned int cnt = 0;
        Ivar *ivs = class_copyIvarList([obj class], &cnt);
        if (!ivs) return;
        NSMutableString *head = [NSMutableString string];
        int nBig = 0;
        for (unsigned int i = 0; i < cnt; i++) {
            const char *n = ivar_getName(ivs[i]);
            const char *t = ivar_getTypeEncoding(ivs[i]);
            if (!n || !t) continue;
            if (t[0] != '@') continue;                      // ★ 只碰对象
            id v = nil;
            @try { v = object_getIvar(obj, ivs[i]); } @catch (NSException *e) { continue; }
            if (!v) continue;
            NSUInteger len = 0;
            if ([v respondsToSelector:@selector(length)]) len = [v length];
            else if ([v respondsToSelector:@selector(count)]) len = [v count];
            [head appendFormat:@"%s=%@(%lu) ", n, NSStringFromClass([v class]), (unsigned long)len];
            if ([v isKindOfClass:[NSDictionary class]]) {
                DumpImageDict((NSDictionary *)v, [NSString stringWithUTF8String:n]);
            } else if ([v isKindOfClass:[NSData class]] && [v length] > 200000) {
                NSString *p = [Dir() stringByAppendingPathComponent:
                    [NSString stringWithFormat:@"ivar_%s_%lu.bin", n, (unsigned long)[v length]]];
                [(NSData *)v writeToFile:p atomically:YES];
                nBig++;
            }
        }
        free(ivs);
        LogLine(@"  ivar 清单(%s): %@", why, head);
        if (nBig) LogLine(@"  （另有 %d 个大 NSData 已落盘）", nBig);
    } @catch (NSException *e) { LogLine(@"  DumpIvars 异常 %@", e); }
}

// ============================================================ ★ 主题原版素材收割

static id gCfg = nil;                            // 插件配置对象
static SEL gLoadSEL = NULL;                      // loadIconMapFromDecryptedDat:
static void (*gLoadIMP)(id, SEL, id) = NULL;     // 它的原始实现

static NSString *ThemeNameFromPath(NSString *p) {
    if (![p isKindOfClass:[NSString class]]) return @"unknown";
    return [[p stringByDeletingLastPathComponent] lastPathComponent] ?: @"unknown";
}

static void SaveOneFile(NSString *theme, NSString *name, NSData *d) {
    @try {
        NSString *safe = [theme stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
        NSString *base = [[Dir() stringByAppendingPathComponent:@"KM"] stringByAppendingPathComponent:safe];
        NSString *rel = [name stringByReplacingOccurrencesOfString:@".." withString:@"_"];
        NSString *p = [base stringByAppendingPathComponent:rel];
        [[NSFileManager defaultManager] createDirectoryAtPath:[p stringByDeletingLastPathComponent]
                                  withIntermediateDirectories:YES attributes:nil error:nil];
        [d writeToFile:p atomically:YES];
    } @catch (NSException *e) { }
}

/// 把 _themeMap 里每一个文件按【原始文件名】落盘到 KM/<主题>/
static int DumpThemeMap(id obj, NSString *theme) {
    int n = 0;
    @try {
        unsigned int cnt = 0;
        Ivar *ivs = class_copyIvarList([obj class], &cnt);
        if (!ivs) return 0;
        for (unsigned int i = 0; i < cnt; i++) {
            const char *in = ivar_getName(ivs[i]);
            const char *it = ivar_getTypeEncoding(ivs[i]);
            if (!in || !it || it[0] != '@') continue;
            if (!strstr(in, "Map")) continue;
            id v = nil;
            @try { v = object_getIvar(obj, ivs[i]); } @catch (NSException *e) { continue; }
            if (![v isKindOfClass:[NSDictionary class]]) continue;
            int got = 0;
            for (id k in (NSDictionary *)v) {
                id vv = ((NSDictionary *)v)[k];
                if (![vv isKindOfClass:[NSData class]]) continue;
                if ([(NSData *)vv length] < 24) continue;
                SaveOneFile(theme, [k description], (NSData *)vv);
                got++;
            }
            if (got) LogLine(@"  >> %s 落盘 %d 个原版文件 -> KM/%@/", in, got, theme);
            n += got;
        }
        free(ivs);
    } @catch (NSException *e) { LogLine(@"  DumpThemeMap 异常 %@", e); }
    return n;
}

static NSMutableSet *LoadDoneSet(void) {
    static NSMutableSet *s = nil;
    if (s) return s;
    s = [NSMutableSet set];
    NSString *p = [Dir() stringByAppendingPathComponent:@"KM/_done.txt"];
    NSString *txt = [NSString stringWithContentsOfFile:p encoding:NSUTF8StringEncoding error:nil];
    for (NSString *l in [txt componentsSeparatedByString:@"\n"])
        if (l.length) [s addObject:l];
    return s;
}

static void MarkDone(NSString *theme) {
    @try {
        NSMutableSet *s = LoadDoneSet();
        if ([s containsObject:theme]) return;
        [s addObject:theme];
        NSString *p = [Dir() stringByAppendingPathComponent:@"KM/_done.txt"];
        NSData *d = [[theme stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:p];
        if (!fh) [d writeToFile:p atomically:YES];
        else { [fh seekToEndOfFile]; [fh writeData:d]; [fh closeFile]; }
    } @catch (NSException *e) { }
}

/// 批量收割：遍历主题目录下所有 keiembox.dat，让插件自己解密，我们抄结果
static void RunBulk(void) {
    @try {
        if (!gCfg || !gLoadIMP) { LogLine(@"批量：还没拿到插件入口，跳过"); return; }
        NSFileManager *fm = [NSFileManager defaultManager];
        NSMutableArray<NSString *> *roots = [NSMutableArray array];
        NSString *r1 = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/ThemeApp/KmTheme"];
        if ([fm fileExistsAtPath:r1]) [roots addObject:r1];
        NSString *r2 = @"/var/mobile/Media/km_bulk";
        if ([fm fileExistsAtPath:r2]) [roots addObject:r2];
        if (!roots.count) { LogLine(@"批量：没找到主题目录"); return; }

        NSMutableArray<NSString *> *todo = [NSMutableArray array];
        NSMutableSet *done = LoadDoneSet();
        for (NSString *root in roots) {
            for (NSString *name in [fm contentsOfDirectoryAtPath:root error:nil]) {
                if ([name hasPrefix:@"."]) continue;
                NSString *dat = [[root stringByAppendingPathComponent:name]
                                 stringByAppendingPathComponent:@"keiembox.dat"];
                if ([fm fileExistsAtPath:dat] && ![done containsObject:name]) [todo addObject:name];
            }
        }
        LogLine(@"批量：已完成 %lu，本次待处理 %lu", (unsigned long)done.count, (unsigned long)todo.count);
        if (!todo.count) return;

        int ok = 0, fail = 0;
        for (NSString *name in todo) {
            @autoreleasepool {
                NSString *dat = nil;
                for (NSString *root in roots) {
                    NSString *c = [[root stringByAppendingPathComponent:name]
                                   stringByAppendingPathComponent:@"keiembox.dat"];
                    if ([fm fileExistsAtPath:c]) { dat = c; break; }
                }
                if (!dat) continue;
                @try {
                    gLoadIMP(gCfg, gLoadSEL, dat);          // ★ 插件自己做解密
                    int n = DumpThemeMap(gCfg, name);       // ★ 抄出全部原版文件
                    if (n > 0) { MarkDone(name); ok++; } else fail++;
                    if ((ok + fail) % 5 == 0)
                        LogLine(@"批量进度 %d/%lu 本个 %d 文件 成功 %d 失败 %d",
                                ok + fail, (unsigned long)todo.count, n, ok, fail);
                } @catch (NSException *e) { fail++; }
            }
        }
        LogLine(@"批量结束：成功 %d 失败 %d 输出在 KM/", ok, fail);
    } @catch (NSException *e) { LogLine(@"批量异常 %@", e); }
}

// ============================================================ 挂钩：两个解密加载入口

typedef void (*IMPV1)(id, SEL, id);

static int InstallLoader(void) {
    EnsureSeen();
    int done = 0;
    for (NSString *cn in PluginClasses()) {
        Class c = objc_getClass(cn.UTF8String);
        if (!c) continue;
        for (NSString *s in @[@"loadIconMapFromDecryptedDat:", @"loadBubbleIconMapFromDecryptedDat:"]) {
            SEL sel = NSSelectorFromString(s);
            Method m = class_getInstanceMethod(c, sel);
            if (!m) continue;
            IMP orig = method_getImplementation(m);
            NSString *idk = [NSString stringWithFormat:@"L:%s|%p", sel_getName(sel), orig];
            if ([gSeen containsObject:idk]) continue;
            [gSeen addObject:idk];
            SEL cs = sel;
            IMP r = imp_implementationWithBlock(^void(id me, id a2) {
                @autoreleasepool {
                    LogLine(@"==== 加载解密 -[%@ %@] %@", NSStringFromClass([me class]),
                            NSStringFromSelector(cs), a2);
                }
                ((IMPV1)orig)(me, cs, a2);
                @try {
                    if (!gCfg) {
                        gCfg = me; gLoadSEL = cs; gLoadIMP = (IMPV1)orig;
                        LogLine(@"已记住插件入口，可批量收割");
                    }
                } @catch (NSException *e) { }
                @try {
                    NSString *tn = ThemeNameFromPath(a2);
                    int n = DumpThemeMap(me, tn);
                    if (n) {
                        MarkDone(tn);
                        LogLine(@"★ 本主题收割完成：%d 个原版文件 -> KM/%@/", n, tn);
                        static volatile int bulkScheduled = 0;
                        if (!bulkScheduled) {
                            bulkScheduled = 1;
                            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                                         (int64_t)(6 * NSEC_PER_SEC)),
                                dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
                                    @autoreleasepool { RunBulk(); }
                                });
                        }
                    }
                } @catch (NSException *e) { }
            });
            method_setImplementation(m, r);
            done++;
            LogLine(@"loader 挂钩 -[%@ %@]", cn, s);
        }
    }
    return done;
}

/// 授权相关：有授权码时不起作用也无害；授权到期后可能有用（只挂确实存在的方法）
static int InstallBypass(void) {
    EnsureSeen();
    NSDictionary *bp = @{
        @"checkAuthabc":                     @YES,
        @"verifySign:canonical:derivedKey:": @YES,
        @"verifyResponseSign:data:nonce:ts:sessionKey:": @YES,
        @"isExpired":                        @NO,
    };
    int done = 0;
    for (NSString *cn in PluginClasses()) {
        Class c = objc_getClass(cn.UTF8String);
        if (!c) continue;
        for (NSString *s in bp) {
            SEL sel = NSSelectorFromString(s);
            Method m = class_getInstanceMethod(c, sel);
            if (!m) continue;
            IMP orig = method_getImplementation(m);
            NSString *idk = [NSString stringWithFormat:@"B:%s|%p", sel_getName(sel), orig];
            if ([gSeen containsObject:idk]) continue;
            [gSeen addObject:idk];
            id forced = bp[s];
            SEL cs = sel;
            IMP r = imp_implementationWithBlock(^id(id me, id a2, id a3, id a4) {
                (void)a2; (void)a3; (void)a4;
                LogLine(@"★ 授权绕过 -[%@ %@] -> %@", NSStringFromClass([me class]),
                        NSStringFromSelector(cs), [forced boolValue] ? @"YES" : @"NO");
                return forced;
            });
            method_setImplementation(m, r);
            done++;
        }
    }
    return done;
}

// ============================================================ 装载

static volatile int gDumpedOnce = 0;

static void InstallAll(int round) {
    @autoreleasepool {
        @try { int n = InstallLoader(); if (n) LogLine(@"第 %d 轮：loader 挂钩 %d 个", round, n); }
        @catch (NSException *e) { }
        @try { int n = InstallBypass(); if (n) LogLine(@"第 %d 轮：授权绕过 %d 个", round, n); }
        @catch (NSException *e) { }
    }
}

__attribute__((constructor))
static void InitDump(void) {
    @autoreleasepool {
        (void)Dir();
        LogLine(@"========== DumpKeiem v8 启动 ==========");
        LogLine(@"输出目录 %@", Dir());
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            double marks[] = {2, 6, 12, 25, 45, 80};
            double prev = 0;
            for (int i = 0; i < 6; i++) {
                double wait = marks[i] - prev;
                if (wait > 0) [NSThread sleepForTimeInterval:wait];
                prev = marks[i];
                @try { InstallAll(i + 1); } @catch (NSException *e) { }
            }
            LogLine(@"初始化流程结束");
            // 万一本次没有任何主题加载动作，也把批量跑起来（收割已下载的主题）
            if (!gDumpedOnce) {
                gDumpedOnce = 1;
                @try { RunBulk(); } @catch (NSException *e) { }
            }
        });
    }
}
