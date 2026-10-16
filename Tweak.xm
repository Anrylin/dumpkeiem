// Tweak.xm —— DumpKeiem v3
// 目的：在插件解密 keiembox.dat 时抓到 key/iv，并顺手导出解密后的原版 UIImage。
//
// v3 相对 v2 的三个关键改动：
//   ① 不再全类扫描（v2 每次枚举 12 万个类，慢），改为 objc_copyClassNamesForImage 只枚举插件镜像；
//   ② 全部动作跑在后台队列，绝不阻塞主线程；
//   ③ 【核心】自实现 mini-fishhook：解析插件镜像的 dyld bind 表，把 CCCrypt 的调用槽换成我们的函数。
//      插件的 AES 方法名是运行时动态注册的，按名字找不到；但 CCCrypt 是 C 函数，绕不过去。
//
// 输出目录：优先 /var/mobile/Media/keiem_dump，写不进去回退到 app 的 Documents/keiem_dump

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dispatch/dispatch.h>
#import <stdlib.h>
#import <string.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <dlfcn.h>

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

static NSString *HexStr(const void *p, size_t n, size_t max) {
    if (!p || !n) return @"";
    size_t m = n < max ? n : max;
    const uint8_t *b = (const uint8_t *)p;
    NSMutableString *s = [NSMutableString stringWithCapacity:m * 2];
    for (size_t i = 0; i < m; i++) [s appendFormat:@"%02x", b[i]];
    return s;
}

// ============================================================ mini-fishhook
// 只依赖 <mach-o/loader.h>，不需要 substrate / ellekit。

typedef struct { const char *name; void *repl; void **orig; int hits; } RebindItem;

static uint64_t rd_uleb(const uint8_t **pp) {
    uint64_t v = 0; int sh = 0; uint8_t c;
    do { c = **pp; (*pp)++; v |= ((uint64_t)(c & 0x7F)) << sh; sh += 7; } while ((c & 0x80) && sh < 64);
    return v;
}
static int64_t rd_sleb(const uint8_t **pp) {
    int64_t v = 0; int sh = 0; uint8_t c;
    do { c = **pp; (*pp)++; v |= ((int64_t)(c & 0x7F)) << sh; sh += 7; } while ((c & 0x80) && sh < 64);
    if (sh < 64 && (c & 0x40)) v |= -((int64_t)1 << sh);
    return v;
}
static const char *rd_cstr(const uint8_t **pp) {
    const char *s = (const char *)*pp;
    while (**pp) (*pp)++;
    (*pp)++;
    return s;
}

/// 在指定镜像里，把 items 里列出的符号的调用槽换成新实现（保存原实现）
static int Rebind(const struct mach_header_64 *mh, intptr_t slide, RebindItem *items, int n) {
    if (!mh || mh->magic != MH_MAGIC_64) return 0;

    const struct dyld_info_command *dyld = NULL;
    const struct segment_command_64 *segs[32];
    int nsegs = 0;

    const uint8_t *p = (const uint8_t *)mh + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_DYLD_INFO_ONLY || lc->cmd == LC_DYLD_INFO)
            dyld = (const struct dyld_info_command *)lc;
        else if (lc->cmd == LC_SEGMENT_64 && nsegs < 32)
            segs[nsegs++] = (const struct segment_command_64 *)lc;
        if (lc->cmdsize == 0) break;
        p += lc->cmdsize;
    }
    if (!dyld) {
        LogLine(@"  !! 该镜像没有 LC_DYLD_INFO（可能用 chained fixups）");
        return 0;
    }

    int total = 0;
    int sampleLogged = 0;
    for (int pass = 0; pass < 2; pass++) {
        uint32_t off  = pass ? dyld->lazy_bind_off : dyld->bind_off;
        uint32_t size = pass ? dyld->lazy_bind_size : dyld->bind_size;
        if (!off || !size) continue;

        const uint8_t *d = (const uint8_t *)mh + off;
        const uint8_t *end = d + size;
        int seg = 0;
        uint64_t seg_off = 0;
        const char *symname = NULL;
        int stop = 0;

        while (d < end && !stop) {
            uint8_t b = *d++;
            uint8_t op = b & 0xF0, imm = b & 0x0F;
            switch (op) {
                case BIND_OPCODE_DONE:
                    if (pass) { symname = NULL; seg_off = 0; }   // lazy：一条一 DONE
                    else stop = 1;
                    break;
                case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: break;
                case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: rd_uleb(&d); break;
                case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: break;
                case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                    symname = rd_cstr(&d);
                    if (symname) {
                        int printable = 1;
                        for (const char *q = symname; *q; q++) {
                            unsigned char u = (unsigned char)*q;
                            if (u < 32 || u > 126) { printable = 0; break; }
                        }
                        // 把所有含 "rypt" 的符号名打出来 —— 彻底确认 CCCrypt 的真名
                        if (printable && strstr(symname, "rypt") && sampleLogged < 24) {
                            LogLine(@"    bind 符号(含 rypt) #%d: %s", sampleLogged, symname);
                            sampleLogged++;
                        }
                    }
                    break;
                case BIND_OPCODE_SET_TYPE_IMM: break;
                case BIND_OPCODE_SET_ADDEND_SLEB: rd_sleb(&d); break;
                case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: seg = imm; seg_off = rd_uleb(&d); break;
                case BIND_OPCODE_ADD_ADDR_ULEB: seg_off += rd_uleb(&d); break;

                case BIND_OPCODE_DO_BIND:
                case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
                case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
                case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: {
                    uint64_t times = 1, skip = 0;
                    if (op == BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB) {
                        times = rd_uleb(&d);
                        skip  = rd_uleb(&d);
                    }
                    if (symname && seg >= 0 && seg < nsegs) {
                        for (uint64_t t = 0; t < times; t++) {
                            uintptr_t slot = (uintptr_t)mh + slide
                                           + segs[seg]->vmaddr + seg_off;
                            for (int k = 0; k < n; k++) {
                                if (items[k].hits) continue;
                                if (strcmp(symname, items[k].name) != 0) continue;
                                void **pp = (void **)slot;
                                void *cur = *pp;
                                if (!cur) continue;
                                // 懒绑定槽里放的可能不是真函数，所以原函数优先用 dlsym 拿到的
                                if (items[k].orig && !*items[k].orig) *items[k].orig = cur;
                                *pp = items[k].repl;
                                items[k].hits++;
                                total++;
                                LogLine(@"重绑定 %s  槽=%p  原=%p", items[k].name, (void *)slot, cur);
                            }
                            seg_off += 8 + skip;
                        }
                    }
                    if (op == BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB) seg_off += rd_uleb(&d);
                    else if (op == BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED) seg_off += (uint64_t)imm * 8;
                    break; }

                default:
                    stop = 1;
                    break;
            }
        }
    }
    return total;
}

// ============================================================ CCCrypt 替换

typedef int (*CCCrypt_t)(uint32_t op, uint32_t alg, uint32_t options,
                        const void *key, size_t keyLen, const void *iv,
                        const void *in, size_t inLen,
                        void *out, size_t outAvail, size_t *moved);
typedef int (*CCCryptorCreate_t)(uint32_t op, uint32_t alg, uint32_t options,
                                const void *key, size_t keyLen, const void *iv, void **ref);

static CCCrypt_t gCCCrypt = NULL;
static CCCryptorCreate_t gCryptorCreate = NULL, gCryptorCreateWithMode = NULL;

static void NoteKey(const char *who, const void *key, size_t keyLen, const void *iv,
                    const void *in, size_t inLen) {
    NSString *kh = HexStr(key, keyLen, 64);
    NSString *ih = HexStr(iv, 16, 16);
    if (!kh.length) return;
    LogLine(@"=== %s 命中 === keyLen=%zu inLen=%zu", who, keyLen, inLen);
    LogLine(@"    KEY = %@", kh);
    LogLine(@"    IV  = %@", ih);
    LogLine(@"    密文头 = %@", HexStr(in, 32, 32));
    NSString *j = [NSString stringWithFormat:
        @"{\"via\":\"%s\",\"keyHex\":\"%@\",\"ivHex\":\"%@\",\"keyLen\":%zu,\"cipherLen\":%zu,"
         "\"cipherHead\":\"%@\"}\n", who, kh, ih, keyLen, inLen, HexStr(in, 32, 32)];
    [j writeToFile:[Dir() stringByAppendingPathComponent:@"key.json"] atomically:YES
          encoding:NSUTF8StringEncoding error:nil];
}

static int my_CCCrypt(uint32_t op, uint32_t alg, uint32_t options,
                      const void *key, size_t keyLen, const void *iv,
                      const void *in, size_t inLen, void *out, size_t outAvail, size_t *moved) {
    @autoreleasepool { NoteKey("CCCrypt", key, keyLen, iv, in, inLen); }
    int r = gCCCrypt ? gCCCrypt(op, alg, options, key, keyLen, iv, in, inLen, out, outAvail, moved) : -1;
    @autoreleasepool {
        size_t mv = moved ? *moved : 0;
        LogLine(@"    返回 %d 明文长度 %zu 明文头 %@", r, mv, HexStr(out, mv ? mv : 32, 48));
        if (in && inLen > 4096) {
            [[NSData dataWithBytes:in length:inLen]
                writeToFile:[Dir() stringByAppendingPathComponent:
                           [NSString stringWithFormat:@"cipher_%zu.bin", inLen]] atomically:YES];
        }
        if (out && mv > 4096) {
            [[NSData dataWithBytes:out length:mv]
                writeToFile:[Dir() stringByAppendingPathComponent:
                           [NSString stringWithFormat:@"plain_%zu.bin", mv]] atomically:YES];
        }
    }
    return r;
}

static int my_CCCryptorCreate(uint32_t op, uint32_t alg, uint32_t options,
                              const void *key, size_t keyLen, const void *iv, void **ref) {
    @autoreleasepool { NoteKey("CCCryptorCreate", key, keyLen, iv, NULL, 0); }
    return gCryptorCreate ? gCryptorCreate(op, alg, options, key, keyLen, iv, ref) : -1;
}

static int my_CCCryptorCreateWithMode(uint32_t op, uint32_t mode, uint32_t alg, uint32_t pad,
                                      const void *iv, const void *key, size_t keyLen,
                                      const void *tweak, size_t tweakLen,
                                      uint32_t numRounds, uint32_t options, void **ref) {
    @autoreleasepool { NoteKey("CCCryptorCreateWithMode", key, keyLen, iv, NULL, 0); }
    if (!gCryptorCreateWithMode) return -1;
    typedef int (*T)(uint32_t, uint32_t, uint32_t, uint32_t, const void *, const void *,
                     size_t, const void *, size_t, uint32_t, uint32_t, void **);
    return ((T)gCryptorCreateWithMode)(op, mode, alg, pad, iv, key, keyLen, tweak, tweakLen,
                                       numRounds, options, ref);
}

// ============================================================ 导出解密后的 UIImage（兜底）

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

/// 把对象的全部 ivar 打出来：名字 / 类型 / 值的类与大小
/// 大块 NSData 直接落盘（很可能是解密后的容器），UIImage 字典直接导 PNG
static void DumpIvars(id obj, const char *why) {
    @try {
        unsigned int cnt = 0;
        Ivar *ivs = class_copyIvarList([obj class], &cnt);
        if (!ivs) return;
        NSMutableString *head = [NSMutableString string];
        for (unsigned int i = 0; i < cnt; i++) {
            const char *n = ivar_getName(ivs[i]);
            const char *t = ivar_getTypeEncoding(ivs[i]);
            if (!n) continue;
            id v = nil;
            @try { v = object_getIvar(obj, ivs[i]); } @catch (NSException *e) { }
            if (!v) continue;
            NSUInteger len = 0;
            if ([v respondsToSelector:@selector(length)]) len = [v length];
            else if ([v respondsToSelector:@selector(count)]) len = [v count];
            [head appendFormat:@"%s:%s=%@(%lu) ", n, t ? t : "?", NSStringFromClass([v class]), (unsigned long)len];

            if ([v isKindOfClass:[NSData class]] && [v length] > 80000) {
                NSString *p = [Dir() stringByAppendingPathComponent:
                    [NSString stringWithFormat:@"ivar_%s_%lu.bin", n, (unsigned long)[v length]]];
                [(NSData *)v writeToFile:p atomically:YES];
                LogLine(@"  >> ivar %s 落盘 %lu 字节 -> %@", n, (unsigned long)[v length], p);
            } else if ([v isKindOfClass:[NSDictionary class]]) {
                DumpImageDict((NSDictionary *)v, [NSString stringWithUTF8String:n]);
                // 字典里也可能塞着大块 NSData
                for (id kk in (NSDictionary *)v) {
                    id vv = ((NSDictionary *)v)[kk];
                    if ([vv isKindOfClass:[NSData class]] && [vv length] > 80000) {
                        NSString *p = [Dir() stringByAppendingPathComponent:
                            [NSString stringWithFormat:@"dict_%s_%@_%lu.bin", n, kk,
                             (unsigned long)[vv length]]];
                        [(NSData *)vv writeToFile:p atomically:YES];
                        LogLine(@"  >> dict %s[%@] 落盘 %lu 字节", n, kk, (unsigned long)[vv length]);
                        break;
                    }
                }
            }
        }
        free(ivs);
        LogLine(@"  ivar 清单(%s): %@", why, head);
    } @catch (NSException *e) { LogLine(@"  DumpIvars 异常 %@", e); }
}

// ============================================================ 只枚举插件镜像的类

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

typedef id (*IMP2)(id, SEL, id, id);
typedef id (*IMP3)(id, SEL, id, id, id);
typedef id (*IMP4)(id, SEL, id, id, id, id);
typedef void (*IMPV1)(id, SEL, id);

/// AES 包装方法（名字可能运行时才注册，所以每次 loader 命中后会重试）
static int InstallAES(void) {
    EnsureSeen();
    NSDictionary *tg = @{
        @"aes256DecryptData:keyString:ivString:": @3,
        @"aes256EncryptData:keyString:ivString:": @3,
        @"aesDecryptData:keyString:iv:":          @3,
        @"aesEncryptData:keyString:iv:":          @3,
        @"aesCrypt:data:keyString:ivString:":     @4,
        @"hmacFromData:key:":                     @2,
    };
    int done = 0;
    for (NSString *cn in PluginClasses()) {
        Class c = objc_getClass(cn.UTF8String);
        if (!c) continue;
        for (NSString *s in tg) {
            SEL sel = NSSelectorFromString(s);
            Method m = class_getInstanceMethod(c, sel);
            if (!m) continue;
            IMP orig = method_getImplementation(m);
            NSString *idk = [NSString stringWithFormat:@"A:%s|%p", sel_getName(sel), orig];
            if ([gSeen containsObject:idk]) continue;
            [gSeen addObject:idk];
            SEL cs = sel;
            int na = [tg[s] intValue];
            @try {
                if (na == 2) {
                    IMP r = imp_implementationWithBlock(^id(id me, id a2, id a3) {
                        LogLine(@"=== AES -[%@ %@]  %@ | %@", NSStringFromClass([me class]),
                                NSStringFromSelector(cs), a2, a3);
                        return ((IMP2)orig)(me, cs, a2, a3);
                    });
                    method_setImplementation(m, r);
                } else if (na == 3) {
                    IMP r = imp_implementationWithBlock(^id(id me, id a2, id a3, id a4) {
                        LogLine(@"=== AES -[%@ %@]", NSStringFromClass([me class]), NSStringFromSelector(cs));
                        LogLine(@"    数据 %@", [a2 isKindOfClass:[NSData class]] ?
                                [NSString stringWithFormat:@"NSData(%lu)", (unsigned long)[a2 length]] : a2);
                        LogLine(@"    密钥 %@", a3);
                        LogLine(@"    IV   %@", a4);
                        if ([a3 isKindOfClass:[NSString class]]) {
                            NoteKey("AES-arg", [(NSString *)a3 UTF8String], [(NSString *)a3 length],
                                    [a4 isKindOfClass:[NSString class]] ? [(NSString *)a4 UTF8String] : NULL,
                                    NULL, 0);
                        } else if ([a3 isKindOfClass:[NSData class]]) {
                            NoteKey("AES-arg", [(NSData *)a3 bytes], [(NSData *)a3 length],
                                    [a4 isKindOfClass:[NSData class]] ? [(NSData *)a4 bytes] : NULL, NULL, 0);
                        }
                        return ((IMP3)orig)(me, cs, a2, a3, a4);
                    });
                    method_setImplementation(m, r);
                } else if (na == 4) {
                    IMP r = imp_implementationWithBlock(^id(id me, id a2, id a3, id a4, id a5) {
                        LogLine(@"=== AES4 -[%@ %@] %@ | %@ | %@ | %@", NSStringFromClass([me class]),
                                NSStringFromSelector(cs), a2, a3, a4, a5);
                        return ((IMP4)orig)(me, cs, a2, a3, a4, a5);
                    });
                    method_setImplementation(m, r);
                }
                done++;
                LogLine(@"AES 挂钩 -[%@ %@]", cn, s);
            } @catch (NSException *e) { }
        }
    }
    return done;
}

// 前置声明：HookViaSlots 的定义在本文件靠后的「装载」段
static int HookViaSlots(const char *sym, void *repl, void **orig);

/// 只做「按值扫槽」这件事。可以在解密之后反复调用：那时懒绑定槽已被 dyld 填上真地址。
static int HookSlotsNow(void) {
    void *rc = dlsym(RTLD_DEFAULT, "CCCrypt");
    if (rc && !gCCCrypt) gCCCrypt = (CCCrypt_t)rc;
    if (!gCryptorCreate) gCryptorCreate = (CCCryptorCreate_t)dlsym(RTLD_DEFAULT, "CCCryptorCreate");
    if (!gCryptorCreateWithMode)
        gCryptorCreateWithMode = (CCCryptorCreate_t)dlsym(RTLD_DEFAULT, "CCCryptorCreateWithMode");
    int h = HookViaSlots("CCCrypt", (void *)my_CCCrypt, NULL);
    h += HookViaSlots("CCCryptorCreate", (void *)my_CCCryptorCreate, NULL);
    h += HookViaSlots("CCCryptorCreateWithMode", (void *)my_CCCryptorCreateWithMode, NULL);
    return h;
}

/// 解密加载入口：参数是 keiembox.dat 的路径；返回后内存里就有原版图了
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
                    if ([a2 isKindOfClass:[NSString class]]) {
                        NSData *raw = [NSData dataWithContentsOfFile:(NSString *)a2];
                        LogLine(@"     磁盘文件 %lu 字节（加密态）", (unsigned long)raw.length);
                    }
                }
                ((IMPV1)orig)(me, cs, a2);
                // ★ 关键时机：原函数刚刚解密过 → dyld 已把 CCCrypt 的懒绑定槽填上真地址。
                //   此刻按值重扫槽位必然命中；之后的每一次解密都会被我们拿到。
                @try {
                    int h = HookSlotsNow();
                    if (h) LogLine(@"★ 解密后重扫槽位命中 %d 个 —— 再切一次主题即可抓到 key", h);
                } @catch (NSException *e) { }
                @try { DumpIvars(me, "after-load"); } @catch (NSException *e) { }
                @try { int n = InstallAES(); if (n) LogLine(@"补挂 AES %d 个", n); } @catch (NSException *e) { }
            });
            method_setImplementation(m, r);
            done++;
            LogLine(@"loader 挂钩 -[%@ %@]", cn, s);
        }
    }
    return done;
}

/// 授权绕过（有授权码时不起作用也无害；主要用来观察授权链路）
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

static int gRebindTotal = 0;

/// 方法一（主力）：不解析 bind 表，直接扫镜像里的符号指针槽。
/// 原理：dyld 已经把真函数地址填进了 __la_symbol_ptr / __got 槽；
///       我们只要找"值等于 dlsym(sym)"的槽，把它换成自己的函数即可。
/// 这种方法对 chained fixups / 经典 bind 都有效，也不受符号名下划线影响。
static int HookViaSlots(const char *sym, void *repl, void **orig) {
    void *real = dlsym(RTLD_DEFAULT, sym);
    if (!real) {
        LogLine(@"  dlsym(%s) 失败（找不到该 C 函数）", sym);
        return 0;
    }
    int hits = 0;
    uint32_t nimg = _dyld_image_count();
    for (uint32_t i = 0; i < nimg; i++) {
        const char *path = _dyld_get_image_name(i);
        if (!path || !strstr(path, PLUGIN_HINT)) continue;
        const struct mach_header_64 *mh =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (mh->magic != MH_MAGIC_64) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);

        const struct segment_command_64 *segs[64];
        int nsegs = 0;
        const uint8_t *p = (const uint8_t *)mh + sizeof(struct mach_header_64);
        for (uint32_t c = 0; c < mh->ncmds && nsegs < 64; c++) {
            const struct load_command *lc = (const struct load_command *)p;
            if (lc->cmd == LC_SEGMENT_64) segs[nsegs++] = (const struct segment_command_64 *)lc;
            if (!lc->cmdsize) break;
            p += lc->cmdsize;
        }
        for (int s = 0; s < nsegs; s++) {
            const struct section_64 *sec = (const struct section_64 *)
                ((const uint8_t *)segs[s] + sizeof(struct segment_command_64));
            for (uint32_t k = 0; k < segs[s]->nsects; k++, sec++) {
                uint32_t t = sec->flags & SECTION_TYPE;
                if (t != S_LAZY_SYMBOL_POINTERS && t != S_NON_LAZY_SYMBOL_POINTERS) continue;
                uintptr_t base = (uintptr_t)mh + slide + sec->addr;
                size_t cnt = (size_t)(sec->size / 8);
                for (size_t j = 0; j < cnt; j++) {
                    void **slot = (void **)(base + j * 8);
                    if (*slot != real) continue;
                    if (orig && !*orig) *orig = *slot;
                    *slot = repl;
                    hits++;
                    LogLine(@"  槽命中 %s  %s.%s[%zu] @%p", sym, segs[s]->segname, sec->sectname, j, (void *)slot);
                }
            }
        }
    }
    return hits;
}

/// 方法二（备用）：解析 bind 表。注意 bind 表里的符号名带前导下划线（_CCCrypt）。
static void DoRebindBindTable(void) {
    RebindItem items[] = {
        { "_CCCrypt",                 (void *)my_CCCrypt,         (void **)&gCCCrypt },
        { "_CCCryptorCreate",         (void *)my_CCCryptorCreate, (void **)&gCryptorCreate },
        { "_CCCryptorCreateWithMode", (void *)my_CCCryptorCreateWithMode,
                                      (void **)&gCryptorCreateWithMode },
    };
    int n = (int)(sizeof(items) / sizeof(items[0]));
    uint32_t nimg = _dyld_image_count();
    for (uint32_t i = 0; i < nimg; i++) {
        const char *path = _dyld_get_image_name(i);
        if (!path || !strstr(path, PLUGIN_HINT)) continue;
        const struct mach_header_64 *mh =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        if (mh->magic != MH_MAGIC_64) continue;
        int h = Rebind(mh, slide, items, n);
        if (h) LogLine(@"  bind 表命中 %d 个", h);
        gRebindTotal += h;
    }
}

static void DoRebind(void) {
    // 先看插件镜像到底加载了没
    int found = 0;
    uint32_t nimg = _dyld_image_count();
    for (uint32_t i = 0; i < nimg; i++) {
        const char *path = _dyld_get_image_name(i);
        if (path && strstr(path, PLUGIN_HINT)) {
            if (!found) LogLine(@"插件镜像已加载: %s", path);
            found++;
        }
    }
    if (!found) { LogLine(@"插件镜像尚未加载"); return; }

    // ★ 先用 dlsym 把「真函数」拿到手。懒绑定槽里的值不可靠，原函数必须从这里来。
    if (!gCCCrypt)          gCCCrypt          = (CCCrypt_t)dlsym(RTLD_DEFAULT, "CCCrypt");
    if (!gCryptorCreate)    gCryptorCreate    = (CCCryptorCreate_t)dlsym(RTLD_DEFAULT, "CCCryptorCreate");
    if (!gCryptorCreateWithMode)
        gCryptorCreateWithMode = (CCCryptorCreate_t)dlsym(RTLD_DEFAULT, "CCCryptorCreateWithMode");
    LogLine(@"dlsym: CCCrypt=%p CCCryptorCreate=%p CCCryptorCreateWithMode=%p",
            (void *)gCCCrypt, (void *)gCryptorCreate, (void *)gCryptorCreateWithMode);

    // 主力：扫非懒绑定槽（__got）——值等于真函数地址的直接换掉
    int h1 = HookViaSlots("CCCrypt", (void *)my_CCCrypt, NULL);
    if (h1) LogLine(@"__got 槽命中 %d 个", h1);

    // 关键：解析 bind 表定位懒绑定槽（__la_symbol_ptr），原函数已由 dlsym 提供
    DoRebindBindTable();
    LogLine(@"重绑定累计命中 %d 个槽", gRebindTotal);
}

static void InstallAll(int round) {
    @autoreleasepool {
        if (!gRebindTotal) {
            @try { DoRebind(); } @catch (NSException *e) { LogLine(@"重绑定异常 %@", e); }
            if (gRebindTotal)
                LogLine(@"第 %d 轮：CCCrypt 重绑定成功（共 %d 个槽）", round, gRebindTotal);
            else
                LogLine(@"第 %d 轮：插件镜像还没加载 / 未找到 CCCrypt 槽", round);
        }
        @try { int n = InstallAES();   if (n) LogLine(@"第 %d 轮：AES 挂钩 %d 个", round, n); } @catch (NSException *e) { }
        @try { int n = InstallLoader();if (n) LogLine(@"第 %d 轮：loader 挂钩 %d 个", round, n); } @catch (NSException *e) { }
        @try { int n = InstallBypass();if (n) LogLine(@"第 %d 轮：授权绕过 %d 个", round, n); } @catch (NSException *e) { }
    }
}

__attribute__((constructor))
static void InitDump(void) {
    @autoreleasepool {
        (void)Dir();
        LogLine(@"========== DumpKeiem v3 启动 ==========");
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
        });
    }
}
