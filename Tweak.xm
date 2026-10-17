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
#define OFF_CFReadStream   0x50a40e8UL   // _CFReadStreamRead
#define OFF_CFWriteStream  0x50a4178UL   // _CFWriteStreamWrite
// ★ 原始 socket（插件自己 socket+connect+send 手搓 HTTP，所以上面那些都抓不到）
#define OFF_send           0x50a4aa0UL
#define OFF_sendto         0x50a4aa8UL
#define OFF_recv           0x50a4a68UL
#define OFF_recvfrom       0x50a4a70UL
#define OFF_write          0x50a4b50UL
#define OFF_read           0x50a4a58UL
#define OFF_socket         0x50a4ad0UL
#define OFF_connect        0x50a46a0UL
#define OFF_close          0x50a4698UL

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

// ---- 原始 HTTP 抓取（插件用手搓 CFRead/WriteStream 走网络，绕过 NSURLSession）----
typedef long (*CFWrite_t)(void *stream, const uint8_t *buf, long len);
typedef long (*CFRead_t)(void *stream, uint8_t *buf, long len);
static CFWrite_t gCFWrite = NULL;
static CFRead_t  gCFRead  = NULL;
static volatile int gRawCount = 0;

static BOOL LooksHTTP(const uint8_t *b, long n) {
    if (!b || n < 8) return NO;
    char tmp[600];
    long m = n < 560 ? n : 560;
    memcpy(tmp, b, m);
    tmp[m] = 0;
    return (strstr(tmp, "HTTP/1.") || strstr(tmp, "Host:") || strstr(tmp, "POST ") ||
            strstr(tmp, "GET ") || strstr(tmp, "Content-Length") || strstr(tmp, "User-Agent"));
}

static long my_CFWrite(void *s, const uint8_t *buf, long len) {
    @try {
        if (gRawCount < 300 && buf && len > 0 && LooksHTTP(buf, len)) {
            gRawCount++;
            NSString *txt = [[NSString alloc] initWithBytes:buf length:MIN((long)500, len)
                                                   encoding:NSUTF8StringEncoding];
            LogLine(@"[RAW-OUT %ldB] %@", len, txt ? txt : HexStr(buf, len, 240));
        }
    } @catch (NSException *e) { }
    return gCFWrite ? gCFWrite(s, buf, len) : -1;
}

static long my_CFRead(void *s, uint8_t *buf, long len) {
    long r = gCFRead ? gCFRead(s, buf, len) : -1;
    @try {
        if (gRawCount < 300 && r > 0 && LooksHTTP(buf, r)) {
            gRawCount++;
            NSString *txt = [[NSString alloc] initWithBytes:buf length:MIN((long)600, r)
                                                   encoding:NSUTF8StringEncoding];
            LogLine(@"[RAW-IN  %ldB] %@", r, txt ? txt : HexStr(buf, r, 240));
        }
    } @catch (NSException *e) { }
    return r;
}

// ---- 密钥包持久化：224/240 字节的加解密一律落盘 + 追踪它从哪个文件读出来的 ----
static NSMutableSet *gSeen = nil;
static void EnsureSeen(void) { if (!gSeen) gSeen = [NSMutableSet set]; }

static volatile int gKpCount = 0;

static void SaveKeyPacket(const char *tag, const void *buf, size_t len) {
    @try {
        if (!buf || len < 200 || len > 300) return;
        if (gKpCount >= 200) return;
        gKpCount++;
        NSString *h = HexStr(buf, len, 64);
        NSString *p = [Dir() stringByAppendingPathComponent:
                       [NSString stringWithFormat:@"KP/%@_%lu_%@.bin", @(tag),
                        (unsigned long)len, [h substringToIndex:16]]];
        [[NSFileManager defaultManager] createDirectoryAtPath:[p stringByDeletingLastPathComponent]
                                  withIntermediateDirectories:YES attributes:nil error:nil];
        [[NSData dataWithBytes:buf length:len] writeToFile:p atomically:YES];
    } @catch (NSException *e) { }
}

static BOOL InterestingSize(NSUInteger n) {
    return (n >= 200 && n <= 300) || (n >= 60 && n <= 80) || (n >= 300 && n <= 400);
}

// ---- 追踪「读文件」：密钥包从哪个文件来的 ----
typedef id (*DataFile_t)(id, SEL, id);

__attribute__((unused)) static void InstallFileHooks(void) {
    EnsureSeen();
    Class NSD = [NSData class];

    NSArray *inits = @[@"initWithContentsOfFile:", @"initWithContentsOfURL:",
                       @"dataWithContentsOfFile:", @"dataWithContentsOfURL:"];
    for (NSString *sn in inits) {
        SEL s = NSSelectorFromString(sn);
        Method m = class_getClassMethod(NSD, s) ?: class_getInstanceMethod(NSD, s);
        if (!m) continue;
        IMP o = method_getImplementation(m);
        NSString *idk = [NSString stringWithFormat:@"F:%s|%p", sel_getName(s), o];
        if ([gSeen containsObject:idk]) continue;
        [gSeen addObject:idk];
        SEL cs = s;
        method_setImplementation(m, imp_implementationWithBlock(^id(id me, id arg) {
            id r = ((id(*)(id, SEL, id))o)(me, cs, arg);
            @try {
                NSUInteger n = [r isKindOfClass:[NSData class]] ? [r length] : 0;
                if (InterestingSize(n)) {
                    NSString *a = [arg isKindOfClass:[NSURL class]]
                                  ? [(NSURL *)arg path] : [arg description];
                    LogLine(@"[FILE-READ %luB] %@  ← %@", (unsigned long)n,
                            [a lastPathComponent], a);
                    SaveKeyPacket("read", [r bytes], n);
                }
            } @catch (NSException *e) { }
            return r;
        }));
    }

    // 写文件：密钥包被存到哪
    NSArray *writes = @[@"writeToFile:atomically:", @"writeToURL:options:error:",
                        @"writeToFile:options:error:"];
    for (NSString *sn in writes) {
        SEL s = NSSelectorFromString(sn);
        Method m = class_getInstanceMethod(NSD, s);
        if (!m) continue;
        IMP o = method_getImplementation(m);
        NSString *idk = [NSString stringWithFormat:@"W:%s|%p", sel_getName(s), o];
        if ([gSeen containsObject:idk]) continue;
        [gSeen addObject:idk];
        SEL cs = s;
        if ([sn isEqualToString:@"writeToFile:atomically:"]) {
            method_setImplementation(m, imp_implementationWithBlock(^BOOL(id me, id path, BOOL atom) {
                @try {
                    NSUInteger n = [me length];
                    if (InterestingSize(n)) {
                        NSString *a = [path isKindOfClass:[NSURL class]]
                                      ? [(NSURL *)path path] : [path description];
                        LogLine(@"[FILE-WRITE %luB] %@  → %@", (unsigned long)n,
                                [a lastPathComponent], a);
                        SaveKeyPacket("write", [me bytes], n);
                    }
                } @catch (NSException *e) { }
                return ((BOOL(*)(id, SEL, id, BOOL))o)(me, cs, path, atom);
            }));
        } else {
            method_setImplementation(m, imp_implementationWithBlock(^BOOL(id me, id arg1, NSUInteger opt, id err) {
                @try {
                    NSUInteger n = [me length];
                    if (InterestingSize(n)) {
                        NSString *a = [arg1 isKindOfClass:[NSURL class]]
                                      ? [(NSURL *)arg1 path] : [arg1 description];
                        LogLine(@"[FILE-WRITE %luB] %@  → %@", (unsigned long)n,
                                [a lastPathComponent], a);
                        SaveKeyPacket("write", [me bytes], n);
                    }
                } @catch (NSException *e) { }
                return ((BOOL(*)(id, SEL, id, NSUInteger, id))o)(me, cs, arg1, opt, err);
            }));
        }
    }
    LogLine(@"  已装文件读写追踪");
}

// ---- 最底层：原始 socket（socket/connect/send/recv/write/read）----
typedef long (*SockSend_t)(int fd, const void *buf, long len, int flags);
typedef long (*SockRecv_t)(int fd, void *buf, long len, int flags);
typedef long (*IORW_t)(int fd, const void *buf, long len);
typedef int  (*SockOpen_t)(int dom, int type, int proto);
typedef int  (*SockConn_t)(int fd, const void *addr, unsigned int alen);
typedef int  (*SockClose_t)(int fd);

static SockSend_t gSend = NULL, gSendto = NULL;
static SockRecv_t gRecv = NULL, gRecvfrom = NULL;
static IORW_t     gWrite = NULL, gRead = NULL;
static SockOpen_t gSocket = NULL;
static SockConn_t gConnect = NULL;
static SockClose_t gClose = NULL;
static volatile int gSockCount = 0;
static volatile long gNsend = 0, gNsendto = 0, gNrecv = 0, gNrecvfrom = 0, gNwrite = 0, gNread = 0;
static volatile long gNhttp = 0;
static volatile long gNconn = 0;
static volatile int  gRawBytes = 0;

// fd → 目标 "ip:port"
#define FDMAP_N 2048
static char gFdDest[FDMAP_N][72];

static void NoteFd(int fd, const char *s) {
    if (fd >= 0 && fd < FDMAP_N && s) { strlcpy(gFdDest[fd], s, 72); }
}
static const char *FdDest(int fd) {
    if (fd >= 0 && fd < FDMAP_N && gFdDest[fd][0]) return gFdDest[fd];
    return "?";
}

__attribute__((unused)) static int my_socket(int dom, int type, int proto) {
    int fd = gSocket ? gSocket(dom, type, proto) : -1;
    if (fd >= 0 && gNconn < 200) {
        gNconn++;
        LogLine(@"[SOCKET fd=%d] domain=%d type=%d proto=%d", fd, dom, type, proto);
    }
    return fd;
}

__attribute__((unused)) static int my_connect(int fd, const void *addr, unsigned int alen) {
    @try {
        const uint8_t *a = (const uint8_t *)addr;
        char buf[72] = "";
        if (a && alen >= 8) {
            int fam = a[1];
            if (fam == 2) {
                snprintf(buf, sizeof buf, "%u.%u.%u.%u:%u", a[4], a[5], a[6], a[7],
                         (unsigned)((a[2] << 8) | a[3]));
            } else if (fam == 30) {
                snprintf(buf, sizeof buf, "[v6]:%u", (unsigned)((a[2] << 8) | a[3]));
            } else {
                snprintf(buf, sizeof buf, "fam=%d", fam);
            }
        }
        NoteFd(fd, buf);
        LogLine(@"[CONNECT fd=%d] %s", fd, buf[0] ? buf : "?");
    } @catch (NSException *e) { }
    return gConnect ? gConnect(fd, addr, alen) : -1;
}

__attribute__((unused)) static int my_close(int fd) {
    if (fd >= 0 && fd < FDMAP_N) gFdDest[fd][0] = 0;
    return gClose ? gClose(fd) : -1;
}

static void LogWire(const char *tag, const void *buf, long len) {
    @try {
        if (gSockCount >= 400 || !buf || len <= 0) return;

        if (!LooksHTTP((const uint8_t *)buf, len)) return;
        gSockCount++;
        gNhttp++;
        NSString *txt = [[NSString alloc] initWithBytes:buf length:MIN((long)700, len)
                                              encoding:NSUTF8StringEncoding];
        LogLine(@"[%s %ldB] %@", tag, len, txt ? txt : HexStr(buf, len, 260));
    } @catch (NSException *e) { }
}

// ★ 无条件记录原始字节（用来逆 receiptSocket 的自定义协议）
static void LogRaw(int fd, const char *tag, const void *buf, long len) {
    @try {
        if (gRawBytes >= 600 || !buf || len <= 0 || len > 200000) return;
        gRawBytes++;
        NSString *txt = [[NSString alloc] initWithBytes:buf length:MIN((long)260, len)
                                              encoding:NSUTF8StringEncoding];
        LogLine(@"[%s fd=%d %s %ldB] %@", tag, fd, FdDest(fd), len,
                txt ? [txt stringByReplacingOccurrencesOfString:@"\n" withString:@"\\n"]
                    : HexStr(buf, len, 200));
    } @catch (NSException *e) { }
}

static long my_send(int fd, const void *buf, long len, int flags) {
    gNsend++;
    LogWire("WIRE-OUT", buf, len);
    LogRaw(fd, "RAW-OUT", buf, len);
    return gSend ? gSend(fd, buf, len, flags) : -1;
}
static long my_sendto(int fd, const void *buf, long len, int flags,
                      const void *addr, unsigned int alen) {
    gNsendto++;
    LogWire("WIRE-OUT", buf, len);
    LogRaw(fd, "RAW-OUT", buf, len);
    typedef long (*T)(int, const void *, long, int, const void *, unsigned int);
    return gSendto ? ((T)gSendto)(fd, buf, len, flags, addr, alen) : -1;
}
static long my_recv(int fd, void *buf, long len, int flags) {
    gNrecv++;
    long r = gRecv ? gRecv(fd, buf, len, flags) : -1;
    if (r > 0) { LogWire("WIRE-IN ", buf, r); LogRaw(fd, "RAW-IN ", buf, r); }
    return r;
}
static long my_recvfrom(int fd, void *buf, long len, int flags, void *addr, void *alen) {
    gNrecvfrom++;
    typedef long (*T)(int, void *, long, int, void *, void *);
    long r = gRecvfrom ? ((T)gRecvfrom)(fd, buf, len, flags, addr, alen) : -1;
    if (r > 0) { LogWire("WIRE-IN ", buf, r); LogRaw(fd, "RAW-IN ", buf, r); }
    return r;
}
static long my_write(int fd, const void *buf, long len) {
    gNwrite++;
    if (len >= 16 && len <= 65536) { LogWire("WIRE-OUT", buf, len); LogRaw(fd, "RAW-OUT", buf, len); }
    return gWrite ? gWrite(fd, buf, len) : -1;
}
static long my_read(int fd, void *buf, long len) {
    gNread++;
    long r = gRead ? gRead(fd, buf, len) : -1;
    if (r >= 16 && r <= 65536) { LogWire("WIRE-IN ", buf, r); LogRaw(fd, "RAW-IN ", buf, r); }
    return r;
}



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

static int gKeysFound = 0;

// ★ 把「设备身份」和「卡密」攒进 identity.json —— PC 端复现请求要用
static void RecordIdentityFromPlain(const void *p, size_t n) {
    @try {
        if (!p || n < 60 || n > 1200) return;
        NSString *s = [[NSString alloc] initWithBytes:p length:n encoding:NSUTF8StringEncoding];
        if (!s) return;
        NSData *d = [s dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *j = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
        if (![j isKindOfClass:[NSDictionary class]]) return;
        NSMutableDictionary *acc = [NSMutableDictionary dictionary];
        NSString *fp = [Dir() stringByAppendingPathComponent:@"identity.json"];
        NSData *old = [NSData dataWithContentsOfFile:fp];
        if (old) {
            NSDictionary *o = [NSJSONSerialization JSONObjectWithData:old options:0 error:nil];
            if ([o isKindOfClass:[NSDictionary class]]) [acc addEntriesFromDictionary:o];
        }
        for (NSString *k in @[@"ts", @"sign", @"uid", @"bundleId", @"version",
                              @"uu", @"vv", @"ov", @"ss", @"bb", @"cmd", @"tt",
                              @"hm", @"dev", @"nonce", @"sessionKey", @"ek", @"iv"])
            if (j[k]) acc[k] = j[k];
        // 那些随机十六进制命名的字段也留着（卡密/设备指纹）
        for (NSString *k in j)
            if (k.length == 32 && [k rangeOfCharacterFromSet:
                    [NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"]].location != NSNotFound)
                acc[k] = j[k];
        NSData *out = [NSJSONSerialization dataWithJSONObject:acc
                        options:NSJSONWritingPrettyPrinted error:nil];
        [out writeToFile:fp atomically:YES];
    } @catch (NSException *e) { }
}

// ★ 每解出一个密钥包，就把 {themeID, iv, key, name} 追加到 keys_found.tsv
static void RecordKeyFromPlain(const void *p, size_t n) {
    @try {
        if (!p || n < 60 || n > 700) return;
        NSString *s = [[NSString alloc] initWithBytes:p length:n encoding:NSUTF8StringEncoding];
        if (!s) return;
        s = [s stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        NSData *d = [[NSData alloc] initWithBase64EncodedString:s
                                                        options:NSDataBase64DecodingIgnoreUnknownCharacters];
        if (!d || d.length < 40) return;
        NSDictionary *j = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
        if (![j isKindOfClass:[NSDictionary class]]) return;
        NSString *tid = j[@"themeID"], *iv = j[@"iv"], *k = j[@"key"], *nm = j[@"name"];
        if (!tid || !iv || !k) return;
        NSString *line = [NSString stringWithFormat:@"%@\t%@\t%@\t%@\n", tid, iv, k, nm ?: @""];
        NSString *fp = [Dir() stringByAppendingPathComponent:@"keys_found.tsv"];
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:fp];
        if (!fh) [line writeToFile:fp atomically:YES encoding:NSUTF8StringEncoding error:nil];
        else { [fh seekToEndOfFile]; [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]]; [fh closeFile]; }
        gKeysFound++;
        LogLine(@"★★ 记录密钥 #%d  %@  iv=%@  key=%@  (%@)", gKeysFound, tid, iv, k, nm ?: @"");
    } @catch (NSException *e) { }
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
        if (inLen <= 512 && in) {
            NSString *t = [[NSString alloc] initWithBytes:in length:inLen encoding:NSUTF8StringEncoding];
            LogLine(@"   [输入全文 %zuB] %@", inLen, t ? t : HexStr(in, inLen, 512));
        }
        if (inLen >= 200 && inLen <= 300) SaveKeyPacket("ccc-in", in, inLen);
        if ((inLen == 195 || inLen == 388 || inLen == 448) && in)
            RecordIdentityFromPlain(in, inLen);
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
        if (mv && mv <= 512 && out) {
            NSString *t = [[NSString alloc] initWithBytes:out length:mv encoding:NSUTF8StringEncoding];
            LogLine(@"   [输出全文 %zuB] %@", mv, t ? t : HexStr(out, mv, 512));
        }
        if (mv >= 200 && mv <= 300) { SaveKeyPacket("ccc-out", out, mv); RecordKeyFromPlain(out, mv); }
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

    struct { unsigned long off; void *repl; void **store; const char *name; } T[] = {
        { OFF_CCCrypt,       (void *)my_CCCrypt, (void **)&gCCCrypt,  "CCCrypt" },
        { OFF_CCHmac,        (void *)my_CCHmac,  (void **)&gCCHmac,   "CCHmac" },
        { OFF_PBKDF2,        (void *)my_PBKDF2,  (void **)&gPBKDF2,   "CCKeyDerivationPBKDF" },
        { OFF_CFWriteStream, (void *)my_CFWrite, (void **)&gCFWrite,  "CFWriteStreamWrite" },
        { OFF_CFReadStream,  (void *)my_CFRead,  (void **)&gCFRead,   "CFReadStreamRead" },
        { OFF_send,          (void *)my_send,    (void **)&gSend,     "send" },
        { OFF_sendto,        (void *)my_sendto,  (void **)&gSendto,   "sendto" },
        { OFF_recv,          (void *)my_recv,    (void **)&gRecv,     "recv" },
        { OFF_recvfrom,      (void *)my_recvfrom,(void **)&gRecvfrom, "recvfrom" },
        { OFF_write,         (void *)my_write,   (void **)&gWrite,    "write" },
        { OFF_read,          (void *)my_read,    (void **)&gRead,     "read" },
    };
    int n = (int)(sizeof(T) / sizeof(T[0]));
    for (int i = 0; i < n; i++) {
        void **slot = (void **)((uintptr_t)base + T[i].off);
        void *cur = *slot;
        if (!cur) { LogLine(@"   !! %s 槽为空，跳过", T[i].name); continue; }
        if (cur == T[i].repl) { LogLine(@"   %s 已挂过", T[i].name); continue; }

        // 原函数统一用 dlsym 取（懒绑定槽里的值不可靠）
        void *real = dlsym(RTLD_DEFAULT, T[i].name);
        if (!real) { LogLine(@"   !! dlsym %s 失败，跳过", T[i].name); continue; }
        if (T[i].store && !*T[i].store) *T[i].store = real;

        // 自校验：槽值必须「落在插件镜像内」(未解析的 stub-helper) 或「等于真函数」
        uintptr_t cu = (uintptr_t)cur, bu = (uintptr_t)base, ru = (uintptr_t)real;
        BOOL inImage = (cu >= bu && cu < bu + 0x8000000UL);
        BOOL isReal  = (cu == ru);
        if (!inImage && !isReal) {
            LogLine(@"   !! %s 槽值 %p 不像 stub-helper 也不像真函数(%p)，跳过",
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

// ============================================================ 收据批量（自动取密钥）
// 插件用独立 socket 拉「收据」(= 密钥包)，HTTP 层钩子看不到。
// 但我们不需要看网络：直接调用插件自己的 fetchAndSaveReceiptForTheme: 让它去取。

static id FindReceiptTarget(void) {
    SEL sel = @selector(fetchAndSaveReceiptForTheme:);
    if (gCfg && [gCfg respondsToSelector:sel]) return gCfg;
    // 兜底：直接实例化（v24 稳定证明崩溃不是它引起的，是 socket 指针钩子）
    for (NSString *cn in PluginClasses()) {
        Class c = objc_getClass(cn.UTF8String);
        if (!c || !class_getInstanceMethod(c, sel)) continue;
        id inst = nil;
        @try { inst = [[c alloc] init]; } @catch (NSException *e) { LogLine(@"alloc init 异常 %@", e); }
        if (inst && [inst respondsToSelector:sel]) {
            LogLine(@"收据目标：alloc init %@", cn);
            return inst;
        }
    }
    LogLine(@"收据目标：还没拿到插件对象（请打开一次主题商店）");
    return nil;
}

static void RunReceipts(void) {
    @try {
        NSFileManager *fm = [NSFileManager defaultManager];
        // 依次尝试多个位置（roothide 下 /var/mobile/Media 可能读不到，沙盒最可靠）
        NSArray *paths = @[
            @"/var/mobile/Media/km_codes.txt",
            [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/km_codes.txt"],
            [[Dir() stringByDeletingLastPathComponent] stringByAppendingPathComponent:@"km_codes.txt"],
        ];
        NSString *lp = nil;
        for (NSString *p in paths)
            if ([fm fileExistsAtPath:p]) { lp = p; break; }

        // 兜底：不区分大小写 + 前缀模糊匹配（防文件名差一两个字符）
        if (!lp) {
            NSArray *dirs = @[@"/var/mobile/Media",
                              [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"],
                              [Dir() stringByDeletingLastPathComponent]];
            for (NSString *d in dirs) {
                for (NSString *f in [fm contentsOfDirectoryAtPath:d error:nil]) {
                    if ([f.lowercaseString hasPrefix:@"km_codes"] ||
                        [f.lowercaseString containsString:@"km_codes"] ||
                        [f.lowercaseString hasPrefix:@"km-codes"]) {
                        lp = [d stringByAppendingPathComponent:f];
                        LogLine(@"收据批量：模糊匹配到清单 %@", lp);
                        break;
                    }
                }
                if (lp) break;
            }
        }

        NSString *txt = lp ? [NSString stringWithContentsOfFile:lp encoding:NSUTF8StringEncoding error:nil] : nil;
        if (!txt) {
            LogLine(@"收据批量：找不到 km_codes.txt（随便放一个位置都行）：");
            for (NSString *p in paths) LogLine(@"    候选：%@", p);
            // ★ 把这两个目录里实际有哪些文件全列出来，好定位你放成了什么名
            for (NSString *d in @[@"/var/mobile/Media",
                                  [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"]]) {
                NSArray *fs = [fm contentsOfDirectoryAtPath:d error:nil];
                LogLine(@"  目录 %@ 共 %lu 项：", d, (unsigned long)fs.count);
                for (NSString *f in fs) {
                    if ([f.lowercaseString containsString:@"km"] ||
                        [f.lowercaseString containsString:@"code"] ||
                        [f.lowercaseString hasSuffix:@".txt"])
                        LogLine(@"      · %@", f);
                }
            }
            return;
        }
        LogLine(@"收据批量：清单来自 %@", lp);
        SEL sel = @selector(fetchAndSaveReceiptForTheme:);
        id tgt = FindReceiptTarget();
        if (!tgt) { LogLine(@"收据批量：找不到实现 fetchAndSaveReceiptForTheme: 的对象"); return; }
        Method m = class_getInstanceMethod([tgt class], sel);
        if (!m) { LogLine(@"收据批量：拿不到 Method"); return; }
        IMP imp = method_getImplementation(m);
        LogLine(@"收据批量：目标 %@  方法 %p", NSStringFromClass([tgt class]), (void *)imp);

        NSString *dp = [Dir() stringByAppendingPathComponent:@"_rcpt_done.txt"];
        NSMutableSet *done = [NSMutableSet set];
        for (NSString *l in [[NSString stringWithContentsOfFile:dp encoding:NSUTF8StringEncoding error:nil]
                             componentsSeparatedByString:@"\n"])
            if (l.length > 3) [done addObject:l];
        NSArray *rows = [txt componentsSeparatedByString:@"\n"];
        LogLine(@"收据批量：清单 %lu 行，已完成 %lu", (unsigned long)rows.count, (unsigned long)done.count);

        int n = 0, limit = 2500;
        for (NSString *row in rows) {
            if (row.length < 6) continue;
            NSString *code = [[row componentsSeparatedByString:@"\t"] firstObject];
            if (!code || code.length < 6 || [done containsObject:code]) continue;
            @try {
                ((void (*)(id, SEL, id))imp)(tgt, sel, code);
                n++;
                NSData *d = [[code stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
                NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:dp];
                if (!fh) [d writeToFile:dp atomically:YES];
                else { [fh seekToEndOfFile]; [fh writeData:d]; [fh closeFile]; }
                if (n % 5 == 0)
                    LogLine(@"收据进度 %d  当前 %@  累计密钥 %d", n, code, gKeysFound);
                // ★ 每 25 个一批，批末等 1 秒 —— 把 90 分钟压到约 4 分钟
                if (n % 25 == 0) [NSThread sleepForTimeInterval:1.0];
            } @catch (NSException *e) { LogLine(@"收据异常 %@ : %@", code, e); }
            if (n >= limit) { LogLine(@"本轮达上限 %d，下轮继续", limit); break; }
        }
        LogLine(@"收据批量结束：本轮 %d，累计密钥 %d", n, gKeysFound);
    } @catch (NSException *e) { LogLine(@"收据批量异常 %@", e); }
}

static void RunBulk(void) {
    @try {
        if (!gCfg || !gLoadIMP) { LogLine(@"批量：还没拿到插件入口，跳过"); return; }
        NSFileManager *fm = [NSFileManager defaultManager];
        NSMutableArray<NSString *> *roots = [NSMutableArray array];
        NSArray *cands = @[
            [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/ThemeApp/KmTheme"],
            [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/ThemeApp/KmBubble"],
            @"/var/mobile/Media/km_bulk",
            @"/var/mobile/Media/km_bulk/KmTheme",
            @"/var/mobile/Media/km_bulk/KmBubble",
        ];
        for (NSString *c in cands)
            if ([fm fileExistsAtPath:c]) [roots addObject:c];
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
        LogLine(@"批量：已完成 %lu，待处理 %lu（目录 %lu 个）",
                (unsigned long)done.count, (unsigned long)todo.count, (unsigned long)roots.count);
        if (!todo.count) return;
        int ok = 0, fail = 0, kp0 = gKpCount;
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
                    if ((ok + fail) % 10 == 0)
                        LogLine(@"批量进度 %d/%lu 成功 %d 失败 %d 新密钥包 %ld",
                                ok + fail, (unsigned long)todo.count, ok, fail,
                                (long)(gKpCount - kp0));
                } @catch (NSException *e) { fail++; }
            }
        }
        LogLine(@"批量结束：成功 %d 失败 %d 本轮新增密钥包 %ld", ok, fail,
                (long)(gKpCount - kp0));
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
                    }
                } @catch (NSException *e) { }
                // ★★ 关键：一拿到插件对象就立刻开始批量取收据（不依赖后台定时器）
                @try {
                    static volatile int rp = 0;
                    if (!rp) {
                        rp = 1;
                        LogLine(@"★★ 插件对象已就位，立刻启动收据批量");
                        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
                            @autoreleasepool { RunReceipts(); }
                        });
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
        // ★ 再钩 fetchAndSaveReceiptForTheme: —— 一有收据活动就捕获插件对象
        SEL fs = NSSelectorFromString(@"fetchAndSaveReceiptForTheme:");
        Method fm = class_getInstanceMethod(c, fs);
        if (fm) {
            IMP fo = method_getImplementation(fm);
            NSString *idk = [NSString stringWithFormat:@"F:%s|%p", sel_getName(fs), fo];
            if (![gSeen containsObject:idk]) {
                [gSeen addObject:idk];
                SEL cs = fs;
                IMP fr = imp_implementationWithBlock(^void(id me, id themeID) {
                    @autoreleasepool {
                        if (me && !gCfg) {
                            gCfg = me;
                            LogLine(@"收据钩子捕获插件对象 %@", NSStringFromClass([me class]));
                        }
                    }
                    ((IMPV1)fo)(me, cs, themeID);
                });
                method_setImplementation(fm, fr);
                done++;
                LogLine(@"loader 挂钩 -[%@ %@]（收据入口）", cn, @"fetchAndSaveReceiptForTheme:");
            }
        }
        // ★ 钩 socketDidDisconnect:withError: —— 卡密认证走 socket，启动后必触发，能抓到对象
        SEL sd = NSSelectorFromString(@"socketDidDisconnect:withError:");
        Method dm = class_getInstanceMethod(c, sd);
        if (dm) {
            IMP dorig = method_getImplementation(dm);
            NSString *idk = [NSString stringWithFormat:@"S:%s|%p", sel_getName(sd), dorig];
            if (![gSeen containsObject:idk]) {
                [gSeen addObject:idk];
                SEL cs = sd;
                IMP dr = imp_implementationWithBlock(^void(id me, id sock, id err) {
                    @autoreleasepool {
                        if (me && !gCfg) {
                            gCfg = me;
                            LogLine(@"socket 回调捕获插件对象 %@", NSStringFromClass([me class]));
                        }
                    }
                    ((void(*)(id, SEL, id, id))dorig)(me, cs, sock, err);
                });
                method_setImplementation(dm, dr);
                done++;
                LogLine(@"loader 挂钩 -[%@ %@]（socket 回调）", cn, @"socketDidDisconnect:withError:");
            }
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

// 只排除明显的系统/无关流量，其余全部记录 —— 之前过滤太严把密钥接口挡掉了
static BOOL IsApiURL(NSString *u) {
    if (!u || u.length == 0) return NO;
    if ([u hasPrefix:@"file:"] || [u hasPrefix:@"data:"] || [u hasPrefix:@"about:"])
        return NO;
    static NSArray *noise = nil;
    if (!noise) noise = @[@"apple.com", @"icloud", @"mzstatic", @"weixin.qq.com",
                          @"qq.com", @"baidu.com", @"akamai", @"gstatic",
                          @"googleapis", @"easemob", @"autonavi", @"amap.com",
                          @"weather", @"wps.com", @"wxqcloud"];
    for (NSString *n in noise)
        if ([u rangeOfString:n options:NSCaseInsensitiveSearch].location != NSNotFound)
            return NO;
    return [u hasPrefix:@"http"];
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

static NSArray<NSString *> *PluginClasses(void);   // 前向声明（定义在后面）

// ============================================================ 信封 / 签名 / 收据 全量抓取
// 目标：把「接口名(context) + 业务参数 + 待签名串 + 签名 + 信封密文」全记下来
//      这样就能在 PC 上完整复现请求，不需要手机参与

static BOOL SeenOnce(NSString *key) {
    EnsureSeen();
    if ([gSeen containsObject:key]) return NO;
    [gSeen addObject:key];
    return YES;
}

__attribute__((unused)) static void InstallEnvelopeHooks(void) {
    SEL s1 = NSSelectorFromString(@"encryptedEnvelopeWithBusinessParams:context:error:");
    SEL s2 = NSSelectorFromString(@"decryptResponseEnvelope:context:error:");
    SEL s3 = NSSelectorFromString(@"signCanonicalString:derivedKey:");
    SEL s4 = NSSelectorFromString(@"canonicalStringWithData:dev:ek:iv:nonce:ts:sessionKey:");
    SEL s5 = NSSelectorFromString(@"fetchAndSaveReceiptForTheme:");
    SEL s6 = NSSelectorFromString(@"verifySign:canonical:derivedKey:");

    NSArray *all = PluginClasses();
    LogLine(@"信封钩子：扫描 %lu 个插件类", (unsigned long)all.count);
    int nFound = 0;

    for (NSString *cn in all) {
        Class c = objc_getClass(cn.UTF8String);
        if (!c) continue;

        // ① 构造加密信封：context 就是接口名
        Method m1 = class_getInstanceMethod(c, s1);
        if (m1) {
            IMP o1 = method_getImplementation(m1);
            if (SeenOnce([NSString stringWithFormat:@"H1:%p", o1])) {
                method_setImplementation(m1, imp_implementationWithBlock(^id(id me, id p, id ctx, void *err) {
                    @try {
                        LogLine(@"[ENV-OUT] %@  context=%@", cn, ctx);
                        LogLine(@"   params = %@", p);
                    } @catch (NSException *e) { }
                    id r = ((id (*)(id, SEL, id, id, void *))o1)(me, s1, p, ctx, err);
                    @try { LogLine(@"   envelope = %@", r); } @catch (NSException *e) { }
                    return r;
                }));
                nFound++;
                LogLine(@"  ✓ %@ encryptedEnvelope...", cn);
            }
        }

        // ② 解密响应信封：context 同样是接口名
        Method m2 = class_getInstanceMethod(c, s2);
        if (m2) {
            IMP o2 = method_getImplementation(m2);
            if (SeenOnce([NSString stringWithFormat:@"H2:%p", o2])) {
                method_setImplementation(m2, imp_implementationWithBlock(^id(id me, id env, id ctx, void *err) {
                    @try { LogLine(@"[ENV-IN ] %@  context=%@  env=%@", cn, ctx, env); }
                    @catch (NSException *e) { }
                    id r = ((id (*)(id, SEL, id, id, void *))o2)(me, s2, env, ctx, err);
                    @try { LogLine(@"   resp = %@", r); } @catch (NSException *e) { }
                    return r;
                }));
                nFound++;
                LogLine(@"  ✓ %@ decryptResponseEnvelope...", cn);
            }
        }

        // ③ 签名核心：待签名串 + 派生密钥 + 结果
        Method m3 = class_getInstanceMethod(c, s3);
        if (m3) {
            IMP o3 = method_getImplementation(m3);
            if (SeenOnce([NSString stringWithFormat:@"H3:%p", o3])) {
                method_setImplementation(m3, imp_implementationWithBlock(^id(id me, id canon, id dk) {
                    id r = nil;
                    @try {
                        r = ((id (*)(id, SEL, id, id))o3)(me, s3, canon, dk);
                        LogLine(@"[SIGN] canonical=%@  derivedKey=%@  → sign=%@", canon, dk, r);
                    } @catch (NSException *e) { }
                    return r;
                }));
                nFound++;
                LogLine(@"  ✓ %@ signCanonicalString:derivedKey:", cn);
            }
        }

        // ④ 待签名串构造：所有输入都在这
        Method m4 = class_getInstanceMethod(c, s4);
        if (m4) {
            IMP o4 = method_getImplementation(m4);
            if (SeenOnce([NSString stringWithFormat:@"H4:%p", o4])) {
                method_setImplementation(m4, imp_implementationWithBlock(
                    ^id(id me, id data, id dev, id ek, id iv, id nonce, id ts, id sk) {
                    id r = nil;
                    @try {
                        r = ((id (*)(id, SEL, id, id, id, id, id, id, id))o4)(
                                me, s4, data, dev, ek, iv, nonce, ts, sk);
                        LogLine(@"[CANON] data=%@ dev=%@ ek=%@ iv=%@ nonce=%@ ts=%@ sk=%@",
                                data, dev, ek, iv, nonce, ts, sk);
                        LogLine(@"   canonical = %@", r);
                    } @catch (NSException *e) { }
                    return r;
                }));
                nFound++;
                LogLine(@"  ✓ %@ canonicalStringWithData:...", cn);
            }
        }

        // ⑤ 收据获取：这是拿密钥的入口
        Method m5 = class_getInstanceMethod(c, s5);
        if (m5) {
            IMP o5 = method_getImplementation(m5);
            if (SeenOnce([NSString stringWithFormat:@"H5:%p", o5])) {
                method_setImplementation(m5, imp_implementationWithBlock(^id(id me, id themeID) {
                    @try { LogLine(@"[RECEIPT] %@  themeID=%@", cn, themeID); }
                    @catch (NSException *e) { }
                    id r = nil;
                    @try { r = ((id (*)(id, SEL, id))o5)(me, s5, themeID); } @catch (NSException *e) { }
                    @try { LogLine(@"[RECEIPT] themeID=%@ 返回 %@", themeID, r); }
                    @catch (NSException *e) { }
                    return r;
                }));
                nFound++;
                LogLine(@"  ✓ %@ fetchAndSaveReceiptForTheme:  ← 关键", cn);
            }
        }

        // ⑥ 签名校验：能看出它比对什么
        Method m6 = class_getInstanceMethod(c, s6);
        if (m6) {
            IMP o6 = method_getImplementation(m6);
            if (SeenOnce([NSString stringWithFormat:@"H6:%p", o6])) {
                method_setImplementation(m6, imp_implementationWithBlock(^BOOL(id me, id sig, id canon, id dk) {
                    BOOL r = NO;
                    @try {
                        r = ((BOOL (*)(id, SEL, id, id, id))o6)(me, s6, sig, canon, dk);
                        LogLine(@"[VERIFY] sig=%@ canonical=%@ dk=%@ → %d", sig, canon, dk, (int)r);
                    } @catch (NSException *e) { }
                    return r;
                }));
                nFound++;
                LogLine(@"  ✓ %@ verifySign:canonical:derivedKey:", cn);
            }
        }
    }
    LogLine(@">>> 信封钩子结果：成功挂钩 %d 个方法", nFound);
    if (nFound == 0)
        LogLine(@">>> !! 一个都没挂上：插件类可能还没加载完，下一轮会再试");
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
    // ⑤ +[NSURL URLWithString:] —— 最全面的入口：任何 URL 构造都会经过这里
    SEL s5 = @selector(URLWithString:);
    Method m5 = class_getClassMethod([NSURL class], s5);
    if (m5) {
        IMP o5 = method_getImplementation(m5);
        HookClass([NSURL class], s5, imp_implementationWithBlock(^id(id cls, NSString *str) {
            @try { if (IsApiURL(str)) NetLog(@"NSURL URLWithString: %@", str); }
            @catch (NSException *e) { }
            return ((id(*)(id, SEL, id))o5)(cls, s5, str);
        }));
    }

    // ⑥ -[NSURLSession dataTaskWithURL:completionHandler:]
    SEL s6 = @selector(dataTaskWithURL:completionHandler:);
    Method m6 = class_getInstanceMethod([NSURLSession class], s6);
    if (m6) {
        IMP o6 = method_getImplementation(m6);
        HookInstance([NSURLSession class], s6,
            imp_implementationWithBlock(^id(id me, NSURL *url, id handler) {
                if (!IsApiURL(url.absoluteString))
                    return ((id(*)(id, SEL, id, id))o6)(me, s6, url, handler);
                NetLog(@"HTTP(url) → %@", url.absoluteString);
                if (!handler) return ((id(*)(id, SEL, id, id))o6)(me, s6, url, handler);
                id wrapped = [^(NSData *d, NSURLResponse *resp, NSError *err) {
                    @try {
                        NSInteger code = [(NSHTTPURLResponse *)resp statusCode];
                        NetLog(@"HTTP(url) ← %ld  %luB  %@", (long)code, (unsigned long)d.length,
                               url.absoluteString);
                        NetLog(@"      resp-bin(%lu): %@", (unsigned long)d.length,
                               HexStr((const uint8_t *)d.bytes, MIN((NSUInteger)64, d.length), 64));
                    } @catch (NSException *e) { }
                    if (handler) ((void(^)(NSData *, NSURLResponse *, NSError *))handler)(d, resp, err);
                } copy];
                return ((id(*)(id, SEL, id, id))o6)(me, s6, url, wrapped);
            }));
    }

    // ⑦ 所有「不带 completionHandler」的任务（delegate 模式）：在 resume 时记录 URL
    SEL s7 = @selector(resume);
    Method m7 = class_getInstanceMethod([NSURLSessionTask class], s7);
    if (m7) {
        IMP o7 = method_getImplementation(m7);
        HookInstance([NSURLSessionTask class], s7, imp_implementationWithBlock(^void(id me) {
            @try {
                NSURLRequest *rq = [me valueForKey:@"originalRequest"];
                if (rq && IsApiURL(rq.URL.absoluteString)) {
                    NetLog(@"TASK → %@ %@", rq.HTTPMethod, rq.URL.absoluteString);
                    if (rq.HTTPBody.length) {
                        NSString *b = [[NSString alloc] initWithData:rq.HTTPBody encoding:NSUTF8StringEncoding];
                        NetLog(@"      req-body: %@", b ? [b substringToIndex:MIN((NSUInteger)800, b.length)]
                                                       : [NSString stringWithFormat:@"<bin %lu>", (unsigned long)rq.HTTPBody.length]);
                    }
                }
            } @catch (NSException *e) { }
            ((void(*)(id, SEL))o7)(me, s7);
        }));
    }

    // ⑨ -[NSURLConnection initWithRequest:delegate:] / +connectionWithRequest:delegate:
    SEL s9 = @selector(initWithRequest:delegate:);
    Method m9 = class_getInstanceMethod([NSURLConnection class], s9);
    if (m9) {
        IMP o9 = method_getImplementation(m9);
        HookInstance([NSURLConnection class], s9,
            imp_implementationWithBlock(^id(id me, NSURLRequest *req, id del) {
                @try { if (IsApiURL(req.URL.absoluteString)) NetLog(@"CONN init → %@", req.URL.absoluteString); }
                @catch (NSException *e) { }
                return ((id(*)(id, SEL, id, id))o9)(me, s9, req, del);
            }));
    }
    SEL s10 = @selector(connectionWithRequest:delegate:);
    Method m10 = class_getClassMethod([NSURLConnection class], s10);
    if (m10) {
        IMP o10 = method_getImplementation(m10);
        HookClass([NSURLConnection class], s10,
            imp_implementationWithBlock(^id(id cls, NSURLRequest *req, id del) {
                @try { if (IsApiURL(req.URL.absoluteString)) NetLog(@"CONN + → %@", req.URL.absoluteString); }
                @catch (NSException *e) { }
                return ((id(*)(id, SEL, id, id))o10)(cls, s10, req, del);
            }));
    }

    // ⑩ -[NSURLSession dataTaskWithRequest:]（delegate 模式）
    SEL s11 = @selector(dataTaskWithRequest:);
    Method m11 = class_getInstanceMethod([NSURLSession class], s11);
    if (m11) {
        IMP o11 = method_getImplementation(m11);
        HookInstance([NSURLSession class], s11,
            imp_implementationWithBlock(^id(id me, NSURLRequest *req) {
                @try { if (IsApiURL(req.URL.absoluteString)) NetLog(@"TASK* → %@ %@", req.HTTPMethod, req.URL.absoluteString); }
                @catch (NSException *e) { }
                return ((id(*)(id, SEL, id))o11)(me, s11, req);
            }));
    }

    // ⑫ +[NSURL URLWithString:relativeToURL:]  ← 插件就是这样拼 URL 的！
    SEL s12 = @selector(URLWithString:relativeToURL:);
    Method m12 = class_getClassMethod([NSURL class], s12);
    if (m12) {
        IMP o12 = method_getImplementation(m12);
        HookClass([NSURL class], s12,
            imp_implementationWithBlock(^id(id cls, NSString *str, NSURL *base) {
                id r = ((id(*)(id, SEL, id, id))o12)(cls, s12, str, base);
                @try {
                    NSString *full = [r absoluteString];
                    if (IsApiURL(full))
                        NetLog(@"NSURL rel: base=%@ + %@ → %@", base, str, full);
                } @catch (NSException *e) { }
                return r;
            }));
    }

    // ⑬ -[NSURL absoluteString] —— 任何取完整 URL 的地方都经过这里
    SEL s13 = @selector(absoluteString);
    Method m13 = class_getInstanceMethod([NSURL class], s13);
    if (m13) {
        IMP o13 = method_getImplementation(m13);
        HookInstance([NSURL class], s13, imp_implementationWithBlock(^id(id me) {
            id r = ((id(*)(id, SEL))o13)(me, s13);
            @try {
                if ([r isKindOfClass:[NSString class]] && IsApiURL(r))
                    NetLog(@"URL.absoluteString = %@", r);
            } @catch (NSException *e) { }
            return r;
        }));
    }

    // ⑭ +[NSURL URLWithString:relativeToURL:] 之外的：NSURLComponents 组装
    Class NSComp = objc_getClass("NSURLComponents");
    if (NSComp) {
        NSArray *sets = @[@"setScheme:", @"setHost:", @"setPath:", @"setQuery:",
                          @"setPort:", @"setPercentEncodedPath:"];
        for (NSString *sn in sets) {
            SEL s = NSSelectorFromString(sn);
            Method m = class_getInstanceMethod(NSComp, s);
            if (!m) continue;
            IMP o = method_getImplementation(m);
            NSString *idk = [NSString stringWithFormat:@"C:%s|%p", sel_getName(s), o];
            if ([gSeen containsObject:idk]) continue;
            [gSeen addObject:idk];
            SEL cs = s;
            method_setImplementation(m, imp_implementationWithBlock(^void(id me, id v) {
                @try { NetLog(@"NSURLComponents %@ = %@", NSStringFromSelector(cs), v); }
                @catch (NSException *e) { }
                ((void(*)(id, SEL, id))o)(me, cs, v);
            }));
        }
        LogLine(@"  net 挂钩 NSURLComponents");
    }

    // ⑮ 打印所有已加载镜像 —— 用来找出真正做 HTTP 的那个 framework
    @try {
        uint32_t n = _dyld_image_count();
        LogLine(@"已加载镜像 %u 个：", n);
        for (uint32_t i = 0; i < n; i++) {
            const char *p = _dyld_get_image_name(i);
            if (p && (strstr(p, "/Application/") || strstr(p, "Framework") ||
                      strstr(p, "WeChat"))) {
                LogLine(@"   [%u] %s", i, p);
            }
        }
    } @catch (NSException *e) { }
}

static void InstallAll(int round) {
    @autoreleasepool {
        LogLine(@"socket 计数: send=%ld sendto=%ld recv=%ld recvfrom=%ld write=%ld read=%ld HTTP=%ld CONN=%ld RAW=%d 密钥=%d",
                gNsend, gNsendto, gNrecv, gNrecvfrom, gNwrite, gNread, gNhttp, gNconn, gRawBytes, gKeysFound);
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
        // ★ 唯一构建标记 —— 一眼确认到底加载的是哪个版本
        LogLine(@"############################################################");
        LogLine(@"##########  DumpKeiem v27  BUILD-C6  2026-10-16  ###########");
        LogLine(@"##########  信封/签名/收据/设备身份 全量采集  ###############");
        LogLine(@"############################################################");
        LogLine(@"输出目录 %@", Dir());
        // 额外写一份版本标记到稳定位置，方便确认
        @try {
            NSString *tag = @"DumpKeiem v27 BUILD-C6\n";
            for (NSString *p in @[@"/var/mobile/Media/keiem_version.txt",
                                  [Dir() stringByAppendingPathComponent:@"VERSION.txt"]])
                [tag writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil];
        } @catch (NSException *e) { }
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
            // ★ 等插件对象（最多 60 秒），然后尝试 alloc init 兜底
            for (int w = 0; w < 30; w++) {
                if (gCfg) break;
                if (w % 5 == 0) LogLine(@"等待插件对象… %d 秒", w * 2);
                [NSThread sleepForTimeInterval:2.0];
            }
            if (!gCfg) {
                LogLine(@"gCfg 未捕获，尝试直接实例化插件对象");
                id tgt = FindReceiptTarget();   // ← 这里才会走 alloc init
                if (tgt) { gCfg = tgt; LogLine(@"直接实例化成功，开始收据批量"); }
            }
            if (gCfg) {
                LogLine(@"插件对象已就位，开始收据批量");
                @try { RunReceipts(); } @catch (NSException *e) { }
                @try { RunBulk(); } @catch (NSException *e) { }
            } else {
                LogLine(@"!!! 三种途径都没拿到插件对象");
            }
            LogLine(@"流程结束（累计密钥 %d）", gKeysFound);
        });
    }
}
