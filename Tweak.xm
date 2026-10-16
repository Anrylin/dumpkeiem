// Tweak.xm —— DumpKeiem v9
//
// 两条路并存，互相备份：
//   【路 A｜已验证可用】让插件自己解密，抄出 _themeMap 里的原版素材（不依赖密钥）
//   【路 B｜本次新增】按【精确槽地址】钩住 CCCrypt / CCHmac / CCKeyDerivationPBKDF，
//                    拿到密钥/IV —— 有了它 PC 上就能离线解全部 5578 个包
//
// 路 B 的关键：槽地址是静态算出来的，不依赖 bind 表解析（那个解析器半路会跑偏）
//   插件 __TEXT vmaddr = 0x0  =>  运行期槽地址 = 插件镜像基址 + 偏移
//   _CCCrypt              +0x50a4038
//   _CCHmac               +0x50a4040
//   _CCKeyDerivationPBKDF +0x50a4048
//
// 输出目录：优先 /var/mobile/Media/keiem_dump，写不进去回退到 app 的 Documents/keiem_dump
//   KM/<主题名>/<原始文件名>   ← 原版素材
//   key.json                  ← ★ 密钥（路 B 命中后出现）
//   cipher_*.bin plain_*.bin  ← 密文/明文对照
//   log.txt

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dispatch/dispatch.h>
#import <stdlib.h>
#import <string.h>
#import <stdint.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <sys/mman.h>
#import <dlfcn.h>

#define PLUGIN_HINT        "NewMessageRingUtil"
#define kDirMedia          @"/var/mobile/Media/keiem_dump"

// 静态槽偏移（相对插件镜像基址）
#define OFF_CCCrypt        0x50a4038UL
#define OFF_CCHmac         0x50a4040UL
#define OFF_PBKDF2         0x50a4048UL

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
        if (!fh) [line writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil];
        else { [fh seekToEndOfFile]; [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]]; [fh closeFile]; }
        NSLog(@"[DumpKeiem] %@", s);
    } @catch (NSException *e) { }
}

static NSString *HexStr(const void *p, size_t n, size_t max) {
    if (!p || !n) return @"";
    size_t m = n < max ? n : max;
    const uint8_t *b = (const uint8_t *)p;
    NSMutableString *s = [NSMutableString stringWithCapacity:m * 2];
    for (size_t i = 0; i < m; i++) [s appendFormat:@"%02x", b[i]];
    return s;
}

// ============================================================ 安全写函数指针槽
// __la_symbol_ptr 通常落在 __DATA_CONST，dyld 做完 fixup 会设为只读。
// 直接写会 EXC_BAD_ACCESS，必须先 vm_protect（VM_PROT_COPY 走 COW，不动共享缓存）。

static int SafeWriteSlot(void **slot, void *val) {
    @try {
        vm_address_t addr = (vm_address_t)slot;
        vm_address_t page = addr & ~(vm_address_t)(vm_page_size - 1);
        vm_size_t span = (vm_size_t)((addr + sizeof(void *)) - page);
        kern_return_t kr = vm_protect(mach_task_self(), page, span, FALSE,
                                      VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        if (kr != KERN_SUCCESS) {
            kr = vm_protect(mach_task_self(), page, span, FALSE, VM_PROT_READ | VM_PROT_WRITE);
        }
        if (kr != KERN_SUCCESS) {
            LogLine(@"  !! vm_protect 失败 kr=%d slot=%p", (int)kr, (void *)slot);
            return 0;
        }
        *slot = val;
        return 1;
    } @catch (NSException *e) { LogLine(@"  !! 写槽异常 %@", e); return 0; }
}

// ============================================================ 路 B：密钥捕获

typedef int (*CCCrypt_t)(uint32_t op, uint32_t alg, uint32_t options,
                        const void *key, size_t keyLen, const void *iv,
                        const void *in, size_t inLen,
                        void *out, size_t outAvail, size_t *moved);
typedef int (*CCHmac_t)(uint32_t alg, const void *key, size_t keyLen,
                        const void *data, size_t dataLen, void *macOut);
typedef int (*PBKDF2_t)(uint32_t alg, const char *pw, size_t pwLen,
                        const uint8_t *salt, size_t saltLen, uint32_t prf,
                        uint32_t rounds, uint8_t *dk, size_t dkLen);

static CCCrypt_t gCCCrypt = NULL;
static CCHmac_t  gCCHmac  = NULL;
static PBKDF2_t  gPBKDF2  = NULL;
static volatile int gBigCipher = 0, gBigPlain = 0;

static void SaveKeyJSON(NSString *via, NSString *keyHex, NSString *ivHex,
                        size_t keyLen, size_t cipherLen, NSString *cipherHead) {
    NSString *j = [NSString stringWithFormat:
        @"{\"via\":\"%@\",\"keyHex\":\"%@\",\"ivHex\":\"%@\",\"keyLen\":%zu,"
         "\"cipherLen\":%zu,\"cipherHead\":\"%@\"}\n",
        via, keyHex, ivHex, keyLen, cipherLen, cipherHead];
    [j writeToFile:[Dir() stringByAppendingPathComponent:@"key.json"] atomically:YES
          encoding:NSUTF8StringEncoding error:nil];
    // 追加历史，避免被后来的覆盖
    NSString *h = [Dir() stringByAppendingPathComponent:@"keys.tsv"];
    NSString *line = [NSString stringWithFormat:@"%@\t%@\t%@\t%zu\n", via, keyHex, ivHex, keyLen];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:h];
    if (!fh) [line writeToFile:h atomically:YES encoding:NSUTF8StringEncoding error:nil];
    else { [fh seekToEndOfFile]; [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]]; [fh closeFile]; }
}

static int my_CCCrypt(uint32_t op, uint32_t alg, uint32_t options,
                      const void *key, size_t keyLen, const void *iv,
                      const void *in, size_t inLen, void *out, size_t outAvail, size_t *moved) {
    @autoreleasepool {
        NSString *kh = HexStr(key, keyLen, 64);
        NSString *ih = HexStr(iv, 16, 16);
        LogLine(@"===== CCCrypt 命中 ===== op=%u alg=%u opt=%u keyLen=%zu inLen=%zu",
                op, alg, options, keyLen, inLen);
        LogLine(@"   KEY = %@", kh);
        LogLine(@"   IV  = %@", ih);
        LogLine(@"   密文头 = %@", HexStr(in, 32, 32));
        if (kh.length) SaveKeyJSON(@"CCCrypt", kh, ih, keyLen, inLen, HexStr(in, 32, 32));
        if (in && inLen > 4096 && !gBigCipher) {
            gBigCipher = 1;
            [[NSData dataWithBytes:in length:inLen]
                writeToFile:[Dir() stringByAppendingPathComponent:
                    [NSString stringWithFormat:@"cipher_%zu.bin", inLen]] atomically:YES];
        }
    }
    int r = gCCCrypt ? gCCCrypt(op, alg, options, key, keyLen, iv, in, inLen, out, outAvail, moved) : -1;
    @autoreleasepool {
        size_t mv = moved ? *moved : 0;
        LogLine(@"   返回 %d 明文长度 %zu 明文头 %@", r, mv, HexStr(out, mv ? mv : 32, 48));
        if (out && mv > 4096 && !gBigPlain) {
            gBigPlain = 1;
            [[NSData dataWithBytes:out length:mv]
                writeToFile:[Dir() stringByAppendingPathComponent:
                    [NSString stringWithFormat:@"plain_%zu.bin", mv]] atomically:YES];
        }
    }
    return r;
}

static int my_CCHmac(uint32_t alg, const void *key, size_t keyLen,
                     const void *data, size_t dataLen, void *macOut) {
    @autoreleasepool {
        LogLine(@"===== CCHmac 命中 ===== alg=%u keyLen=%zu dataLen=%zu", alg, keyLen, dataLen);
        LogLine(@"   HMAC-KEY  = %@", HexStr(key, keyLen, 64));
        LogLine(@"   HMAC-DATA = %@", HexStr(data, dataLen, 64));
    }
    return gCCHmac ? gCCHmac(alg, key, keyLen, data, dataLen, macOut) : -1;
}

static int my_PBKDF2(uint32_t alg, const char *pw, size_t pwLen,
                     const uint8_t *salt, size_t saltLen, uint32_t prf,
                     uint32_t rounds, uint8_t *dk, size_t dkLen) {
    @autoreleasepool {
        LogLine(@"===== PBKDF2 命中 ===== alg=%u rounds=%u dkLen=%zu prf=%u", alg, rounds, dkLen, prf);
        LogLine(@"   口令 = %@", [NSString stringWithFormat:@"%.*s", (int)(pwLen < 200 ? pwLen : 200), pw ?: ""]);
        LogLine(@"   口令hex = %@", HexStr(pw, pwLen, 96));
        LogLine(@"   salt = %@", HexStr(salt, saltLen, 64));
    }
    int r = gPBKDF2 ? gPBKDF2(alg, pw, pwLen, salt, saltLen, prf, rounds, dk, dkLen) : -1;
    @autoreleasepool { LogLine(@"   派生结果 = %@", HexStr(dk, dkLen, 64)); }
    return r;
}

static void *PluginBase(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *p = _dyld_get_image_name(i);
        if (p && strstr(p, PLUGIN_HINT)) return (void *)_dyld_get_image_header(i);
    }
    return NULL;
}

static void InstallCryptoHooks(void) {
    void *base = PluginBase();
    if (!base) { LogLine(@"路B：插件镜像尚未加载"); return; }
    if (!gCCCrypt) gCCCrypt = (CCCrypt_t)dlsym(RTLD_DEFAULT, "CCCrypt");
    if (!gCCHmac)  gCCHmac  = (CCHmac_t)dlsym(RTLD_DEFAULT, "CCHmac");
    if (!gPBKDF2)  gPBKDF2  = (PBKDF2_t)dlsym(RTLD_DEFAULT, "CCKeyDerivationPBKDF");
    LogLine(@"路B：镜像基址 %p  dlsym CCCrypt=%p CCHmac=%p PBKDF2=%p",
            base, (void *)gCCCrypt, (void *)gCCHmac, (void *)gPBKDF2);

    struct { unsigned long off; void *repl; void **slot; const char *name; } T[] = {
        { OFF_CCCrypt, (void *)my_CCCrypt, NULL, "CCCrypt" },
        { OFF_CCHmac,  (void *)my_CCHmac,  NULL, "CCHmac" },
        { OFF_PBKDF2,  (void *)my_PBKDF2,  NULL, "CCKeyDerivationPBKDF" },
    };
    for (int i = 0; i < 3; i++) {
        void **slot = (void **)((uintptr_t)base + T[i].off);
        void *cur = *slot;
        LogLine(@"   %s 槽 %p 当前值 %p", T[i].name, (void *)slot, cur);
        if (!cur) { LogLine(@"   !! %s 槽为空，跳过", T[i].name); continue; }
        if (cur == T[i].repl) { LogLine(@"   %s 已挂过", T[i].name); continue; }
        void *real = NULL;
        if (i == 0) real = (void *)gCCCrypt;
        else if (i == 1) real = (void *)gCCHmac;
        else real = (void *)gPBKDF2;
        if (!real) { LogLine(@"   !! dlsym %s 失败，跳过", T[i].name); continue; }
        // ★ 自校验：槽里的值必须「像未解析的 stub-helper（落在插件镜像内）」
        //   或「等于 dlsym 拿到的真函数」。两者都不是 → 偏移不对，绝不写，防止挂错函数导致崩溃。
        uintptr_t cu = (uintptr_t)cur, bu = (uintptr_t)base, ru = (uintptr_t)real;
        BOOL inImage = (cu >= bu && cu < bu + 0x8000000UL);
        BOOL isReal  = (cu == ru);
        if (!inImage && !isReal) {
            LogLine(@"   !! %s 槽值 %p 不像 stub-helper 也不像真函数(%p)，偏移可能不对，跳过",
                    T[i].name, cur, real);
            continue;
        }
        if (SafeWriteSlot(slot, T[i].repl))
            LogLine(@"   ✅ %s 已挂钩（原函数 %p，槽原值 %p，%s）", T[i].name, real, cur,
                    isReal ? @"已解析" : @"懒绑定");
    }
}

// ============================================================ 路 A：抄原版素材

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

static void DumpImageDict(NSDictionary *map, NSString *tag) {
    @try {
        if (![map isKindOfClass:[NSDictionary class]] || ![map count]) return;
        NSString *sub = [Dir() stringByAppendingPathComponent:@"icons"];
        [[NSFileManager defaultManager] createDirectoryAtPath:sub withIntermediateDirectories:YES
                                  attributes:nil error:nil];
        int n = 0;
        for (id k in map) {
            id v = map[k];
            if (![v isKindOfClass:[UIImage class]]) continue;
            NSData *png = UIImagePNGRepresentation((UIImage *)v);
            if (!png) continue;
            NSString *nm = [[k description] stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
            [png writeToFile:[sub stringByAppendingPathComponent:[nm stringByAppendingString:@".png"]]
                  atomically:YES];
            if (++n >= 5000) break;
        }
        if (n) LogLine(@"  >> 导出 %@ 图像 %d 张", tag, n);
    } @catch (NSException *e) { }
}

static void DumpIvars(id obj, const char *why) {
    @try {
        unsigned int cnt = 0;
        Ivar *ivs = class_copyIvarList([obj class], &cnt);
        if (!ivs) return;
        NSMutableString *head = [NSMutableString string];
        for (unsigned int i = 0; i < cnt; i++) {
            const char *n = ivar_getName(ivs[i]);
            const char *t = ivar_getTypeEncoding(ivs[i]);
            if (!n || !t || t[0] != '@') continue;
            id v = nil;
            @try { v = object_getIvar(obj, ivs[i]); } @catch (NSException *e) { continue; }
            if (!v) continue;
            if ([v isKindOfClass:[NSDictionary class]]) {
                DumpImageDict((NSDictionary *)v, [NSString stringWithUTF8String:n]);
            } else if ([v isKindOfClass:[NSData class]] && [v length] > 200000) {
                [[NSData dataWithBytes:[v bytes] length:[v length]]
                    writeToFile:[Dir() stringByAppendingPathComponent:
                        [NSString stringWithFormat:@"ivar_%s_%lu.bin", n, (unsigned long)[v length]]]
                    atomically:YES];
            }
            [head appendFormat:@"%s ", n];
        }
        free(ivs);
        LogLine(@"  ivar 清单(%s): %@", why, head);
    } @catch (NSException *e) { }
}

static id gCfg = nil;
static SEL gLoadSEL = NULL;
static void (*gLoadIMP)(id, SEL, id) = NULL;

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

static int DumpThemeMap(id obj, NSString *theme) {
    int n = 0;
    @try {
        unsigned int cnt = 0;
        Ivar *ivs = class_copyIvarList([obj class], &cnt);
        if (!ivs) return 0;
        for (unsigned int i = 0; i < cnt; i++) {
            const char *in = ivar_getName(ivs[i]);
            const char *it = ivar_getTypeEncoding(ivs[i]);
            if (!in || !it || it[0] != '@' || !strstr(in, "Map")) continue;
            id v = nil;
            @try { v = object_getIvar(obj, ivs[i]); } @catch (NSException *e) { continue; }
            if (![v isKindOfClass:[NSDictionary class]]) continue;
            int got = 0;
            for (id k in (NSDictionary *)v) {
                id vv = ((NSDictionary *)v)[k];
                if (![vv isKindOfClass:[NSData class]] || [(NSData *)vv length] < 24) continue;
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
    for (NSString *l in [txt componentsSeparatedByString:@"\n"]) if (l.length) [s addObject:l];
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
        for (NSString *root in roots)
            for (NSString *name in [fm contentsOfDirectoryAtPath:root error:nil]) {
                if ([name hasPrefix:@"."]) continue;
                NSString *dat = [[root stringByAppendingPathComponent:name]
                                 stringByAppendingPathComponent:@"keiembox.dat"];
                if ([fm fileExistsAtPath:dat] && ![done containsObject:name]) [todo addObject:name];
            }
        LogLine(@"批量：已完成 %lu，待处理 %lu", (unsigned long)done.count, (unsigned long)todo.count);
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
                    gLoadIMP(gCfg, gLoadSEL, dat);
                    int n = DumpThemeMap(gCfg, name);
                    if (n > 0) { MarkDone(name); ok++; } else fail++;
                    if ((ok + fail) % 5 == 0)
                        LogLine(@"批量进度 %d/%lu 成功 %d 失败 %d",
                                ok + fail, (unsigned long)todo.count, ok, fail);
                } @catch (NSException *e) { fail++; }
            }
        }
        LogLine(@"批量结束：成功 %d 失败 %d", ok, fail);
    } @catch (NSException *e) { LogLine(@"批量异常 %@", e); }
}

// ============================================================ 挂钩 loader

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
                        LogLine(@"已记住插件入口");
                    }
                } @catch (NSException *e) { }
                @try {
                    NSString *tn = ThemeNameFromPath(a2);
                    int n = DumpThemeMap(me, tn);
                    if (n) {
                        MarkDone(tn);
                        LogLine(@"★ 本主题收割完成：%d 个原版文件 -> KM/%@/", n, tn);
                        static volatile int bs = 0;
                        if (!bs) {
                            bs = 1;
                            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(6 * NSEC_PER_SEC)),
                                dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
                                    @autoreleasepool { RunBulk(); }
                                });
                        }
                    }
                } @catch (NSException *e) { }
                @try {
                    static volatile int iv = 0;
                    if (!iv) {
                        iv = 1;
                        id strong = me;
                        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)),
                            dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
                                @autoreleasepool { DumpIvars(strong, "after-load"); }
                            });
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

static int InstallBypass(void) {
    EnsureSeen();
    NSDictionary *bp = @{
        @"checkAuthabc": @YES,
        @"verifySign:canonical:derivedKey:": @YES,
        @"verifyResponseSign:data:nonce:ts:sessionKey:": @YES,
        @"isExpired": @NO,
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

// ============================================================ 路 C：网络监听（找密钥接口）
// 插件的接口路径是运行时拼装的（二进制里没有明文 /api/），所以直接监听 HTTP：
// 把主题商城域名下的每个请求 URL / 请求体 / 响应体都记下来 —— 密钥接口自然现形。

static volatile int gNetCount = 0;

static BOOL IsApiURL(NSString *u) {
    if (!u || u.length == 0) return NO;
    return [u containsString:@"18179"] || [u containsString:@"api/theme"] ||
           [u containsString:@"134.122.170.72"] || [u containsString:@"18899/upload"];
}

static void NetLog(NSString *fmt, ...) {
    if (gNetCount > 600) return;
    @try {
        va_list ap; va_start(ap, fmt);
        NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
        va_end(ap);
        LogLine(@"[NET] %@", s);
        gNetCount++;
    } @catch (NSException *e) { }
}

static void HookInstance(Class c, SEL sel, IMP repl) {
    Method m = class_getInstanceMethod(c, sel);
    if (!m) { LogLine(@"  net: 没有 -[%@ %@]", NSStringFromClass(c), NSStringFromSelector(sel)); return; }
    NSString *idk = [NSString stringWithFormat:@"N:%s|%p", sel_getName(sel), method_getImplementation(m)];
    if ([gSeen containsObject:idk]) return;
    [gSeen addObject:idk];
    method_setImplementation(m, repl);
    LogLine(@"  net 挂钩 -[%@ %@]", NSStringFromClass(c), NSStringFromSelector(sel));
}

static void HookClass(Class c, SEL sel, IMP repl) {
    Method m = class_getClassMethod(c, sel);
    if (!m) { LogLine(@"  net: 没有 +[%@ %@]", NSStringFromClass(c), NSStringFromSelector(sel)); return; }
    NSString *idk = [NSString stringWithFormat:@"NC:%s|%p", sel_getName(sel), method_getImplementation(m)];
    if ([gSeen containsObject:idk]) return;
    [gSeen addObject:idk];
    method_setImplementation(m, repl);
    LogLine(@"  net 挂钩 +[%@ %@]", NSStringFromClass(c), NSStringFromSelector(sel));
}

static void InstallNetworkLogger(void) {
    EnsureSeen();

    // ① +[NSURLRequest requestWithURL:]
    SEL s1 = @selector(requestWithURL:);
    Method m1 = class_getClassMethod([NSURLRequest class], s1);
    if (m1) {
        IMP o1 = method_getImplementation(m1);
        HookClass([NSURLRequest class], s1, imp_implementationWithBlock(^id(id cls, NSURL *url) {
            @try { if (IsApiURL(url.absoluteString)) NetLog(@"REQ +NSURLRequest %@", url.absoluteString); }
            @catch (NSException *e) { }
            return ((id(*)(id, SEL, id))o1)(cls, s1, url);
        }));
    }

    // ② -[NSMutableURLRequest setURL:]
    SEL s2 = @selector(setURL:);
    Method m2 = class_getInstanceMethod([NSMutableURLRequest class], s2);
    if (m2) {
        IMP o2 = method_getImplementation(m2);
        HookInstance([NSMutableURLRequest class], s2, imp_implementationWithBlock(^void(id me, NSURL *url) {
            @try { if (IsApiURL(url.absoluteString)) NetLog(@"REQ setURL %@", url.absoluteString); }
            @catch (NSException *e) { }
            ((void(*)(id, SEL, id))o2)(me, s2, url);
        }));
    }

    // ③ -[NSURLSession dataTaskWithRequest:completionHandler:]  ← 主战场
    SEL s3 = @selector(dataTaskWithRequest:completionHandler:);
    Method m3 = class_getInstanceMethod([NSURLSession class], s3);
    if (m3) {
        IMP o3 = method_getImplementation(m3);
        HookInstance([NSURLSession class], s3,
            imp_implementationWithBlock(^id(id me, NSURLRequest *req, id handler) {
                NSString *u = req.URL.absoluteString;
                if (!IsApiURL(u))
                    return ((id(*)(id, SEL, id, id))o3)(me, s3, req, handler);
                @try {
                    NetLog(@"HTTP → %@ %@", req.HTTPMethod, u);
                    if (req.HTTPBody.length) {
                        NSString *b = [[NSString alloc] initWithData:req.HTTPBody encoding:NSUTF8StringEncoding];
                        NetLog(@"      req-body: %@", b ? [b substringToIndex:MIN((NSUInteger)600, b.length)]
                                                       : [NSString stringWithFormat:@"<bin %lu>", (unsigned long)req.HTTPBody.length]);
                    }
                } @catch (NSException *e) { }
                if (!handler)
                    return ((id(*)(id, SEL, id, id))o3)(me, s3, req, handler);
                id wrapped = [^(NSData *d, NSURLResponse *resp, NSError *err) {
                    @try {
                        NSInteger code = [(NSHTTPURLResponse *)resp statusCode];
                        NetLog(@"HTTP ← %ld  %luB  %@", (long)code, (unsigned long)d.length, u);
                        if (d.length) {
                            NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
                            if (s) NetLog(@"      resp: %@", [s substringToIndex:MIN((NSUInteger)1500, s.length)]);
                            else {
                                // 二进制响应：前 64 字节 hex —— 密钥包会是 224/240 字节
                                const uint8_t *p = (const uint8_t *)d.bytes;
                                NSMutableString *hx = [NSMutableString string];
                                for (NSUInteger i = 0; i < MIN((NSUInteger)64, d.length); i++)
                                    [hx appendFormat:@"%02x", p[i]];
                                NetLog(@"      resp-bin(%lu): %@", (unsigned long)d.length, hx);
                            }
                        }
                    } @catch (NSException *e) { }
                    if (handler) ((void(^)(NSData *, NSURLResponse *, NSError *))handler)(d, resp, err);
                } copy];
                return ((id(*)(id, SEL, id, id))o3)(me, s3, req, wrapped);
            }));
    }

    // ④ +[NSURLConnection sendSynchronousRequest:returningResponse:error:]
    SEL s4 = @selector(sendSynchronousRequest:returningResponse:error:);
    Method m4 = class_getClassMethod([NSURLConnection class], s4);
    if (m4) {
        IMP o4 = method_getImplementation(m4);
        HookClass([NSURLConnection class], s4,
            imp_implementationWithBlock(^NSData *(id cls, NSURLRequest *req, NSURLResponse **resp, NSError **err) {
                @try { if (IsApiURL(req.URL.absoluteString)) NetLog(@"SYNC → %@", req.URL.absoluteString); }
                @catch (NSException *e) { }
                NSData *d = ((NSData *(*)(id, SEL, id, void *, void *))o4)(cls, s4, req, resp, err);
                @try {
                    if (IsApiURL(req.URL.absoluteString)) {
                        NetLog(@"SYNC ← %luB %@", (unsigned long)d.length, req.URL.absoluteString);
                        NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
                        if (s) NetLog(@"      resp: %@", [s substringToIndex:MIN((NSUInteger)1500, s.length)]);
                    }
                } @catch (NSException *e) { }
                return d;
            }));
    }
}

// ============================================================ 装载

static void InstallAll(int round) {
    @autoreleasepool {
        @try { if (round == 1) InstallNetworkLogger(); } @catch (NSException *e) { }
        @try { InstallCryptoHooks(); } @catch (NSException *e) { }
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
        LogLine(@"========== DumpKeiem v9 启动 ==========");
        LogLine(@"输出目录 %@", Dir());
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            double marks[] = {1, 3, 6, 12, 25, 45, 80};
            double prev = 0;
            for (int i = 0; i < 7; i++) {
                double wait = marks[i] - prev;
                if (wait > 0) [NSThread sleepForTimeInterval:wait];
                prev = marks[i];
                @try { InstallAll(i + 1); } @catch (NSException *e) { }
            }
            LogLine(@"初始化流程结束");
            @try { RunBulk(); } @catch (NSException *e) { }
        });
    }
}
