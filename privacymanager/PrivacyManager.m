// PrivacyManager.m — 隐私与安全性 设置面板（PreferenceBundle，原生 PSListController + PSSpecifier）
//
// 设计目标：成为系统「设置 → 隐私与安全性」的实时镜像。
//   - App 列表直接来自系统真相源 /var/mobile/Library/TCC/TCC.db（与系统面板完全一致：那边有 这边就有）
//   - 每个 App 的 7 类权限开关直接读写同一个 TCC.db（你开他就开 你关他就关，双向同步）
// 运行于 Settings.app 进程（platform-application，已脱离沙盒），可直读写 TCC.db。
//
// 编译: clang -dynamiclib (arm64+arm64e) -> PrivacyManager（无扩展名）放入 .bundle

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <sqlite3.h>
#import <sys/sysctl.h>
#import <signal.h>
#import <time.h>

#pragma mark - 前向声明（避免私有头依赖）
@interface PSViewController : UIViewController @end
@interface PSListController : PSViewController
- (id)specifiers;
- (id)tableView;
- (void)reloadSpecifiers;
- (void)reloadSpecifier:(id)specifier;
- (void)setScrollEnabled:(BOOL)enabled;
@end

// PSSpecifier 运行时由 Preference.framework（被 PreferenceLoader 载入 Settings）提供，
// 这里只声明我们用到的接口，避免链接期依赖。
@interface PSSpecifier : NSObject
+ (id)preferenceSpecifierNamed:(NSString *)name target:(id)target set:(SEL)setSelector get:(SEL)getSelector detail:(Class)detailClass cell:(int)cellType edit:(Class)editClass;
- (void)setProperty:(id)property forKey:(NSString *)key;
- (id)propertyForKey:(NSString *)key;
- (void)setAction:(SEL)action;
@end

// PSSpecifier cell 类型常量（与 Preferences.framework 完全一致，抄错会崩）
// 真实值：TitleValue=0, Group=1, Switch=2, Button=3, EditText=4, Segment=5, StaticText=6, Link=7
enum {
    PMCellTitleValue = 0,
    PMCellGroup = 1,
    PMCellSwitch = 2,
    PMCellButton = 3,
    PMCellEditText = 4,
    PMCellSegment = 5,
    PMCellStaticText = 6,
    PMCellLink = 7
};

// Security.framework 在 iOS SDK 中被限制为 macOS 专有；运行时经 dlsym 解析，
// 避免把受限符号变成 dylib 的「导入未定义符号」导致 dyld 加载失败、面板静默消失。
typedef CFTypeRef SecStaticCodeRef;
typedef CFTypeRef SecRequirementRef;
typedef uint32_t SecCSFlags;
#define kSecCSDefaultFlags 0
#define kSecCSRequirementInformation 1
#define errSecSuccess 0

#pragma mark - 权限枚举与元数据
typedef NS_ENUM(NSInteger, PMPerm) {
    PMPermPhotos = 0,
    PMPermLocalNetwork,
    PMPermMicrophone,
    PMPermCamera,
    PMPermLocation,
    PMPermTracking,
    PMPermContacts,
    PMPermCount
};
// 状态: -1 未知(无记录/不可读) 0 拒绝 2 允许 3 受限
static NSString *PM_permName(NSInteger p) {
    switch (p) {
        case PMPermPhotos:       return @"照片";
        case PMPermLocalNetwork: return @"本地网络";
        case PMPermMicrophone:   return @"麦克风";
        case PMPermCamera:       return @"相机";
        case PMPermLocation:     return @"定位";
        case PMPermTracking:     return @"跟踪";
        case PMPermContacts:     return @"通讯录";
        default: return @"?";
    }
}
static NSString *PM_permKey(NSInteger p) {
    switch (p) {
        case PMPermPhotos:       return @"photos";
        case PMPermLocalNetwork: return @"localnetwork";
        case PMPermMicrophone:   return @"microphone";
        case PMPermCamera:       return @"camera";
        case PMPermLocation:     return @"location";
        case PMPermTracking:     return @"tracking";
        case PMPermContacts:     return @"contacts";
        default: return @"?";
    }
}
// 该权限对应的 TCC service 候选（现代优先）。本地网络为空数组（非 TCC）。
static NSArray *PM_permServices(NSInteger p) {
    switch (p) {
        case PMPermPhotos:       return @[@"kTCCServicePhotos"];
        case PMPermMicrophone:   return @[@"kTCCServiceMicrophone"];
        case PMPermCamera:       return @[@"kTCCServiceCamera"];
        case PMPermLocation:     return @[@"kTCCServiceLocation", @"kTCCServiceLocationAlways"];
        case PMPermTracking:     return @[@"kTCCServiceUserTracking"];
        case PMPermContacts:     return @[@"kTCCServiceContacts", @"kTCCServiceAddressBook"];
        default: return @[];
    }
}
static BOOL PM_permIsTCC(NSInteger p) {
    return PM_permServices(p).count > 0;
}

// 用于「枚举 App」的隐私类 service 全集（与系统隐私面板对应）
static NSArray *PM_privacyServices(void) {
    return @[@"kTCCServicePhotos", @"kTCCServiceMicrophone", @"kTCCServiceCamera",
             @"kTCCServiceLocation", @"kTCCServiceLocationAlways",
             @"kTCCServiceUserTracking", @"kTCCServiceContacts", @"kTCCServiceAddressBook"];
}

#pragma mark - TCC 数据库读写
static NSString *const kTCCDBPath = @"/var/mobile/Library/TCC/TCC.db";

static sqlite3 *PM_openTCC(void) {
    sqlite3 *db = NULL;
    if (sqlite3_open([kTCCDBPath UTF8String], &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return NULL;
    }
    return db;
}

// 探测 access 表的列名，兼容 iOS 15/16/17 不同 schema
static NSArray *PM_accessColumns(void) {
    NSMutableArray *cols = [NSMutableArray array];
    sqlite3 *db = PM_openTCC();
    if (!db) return cols;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "PRAGMA table_info(access)", -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *name = (const char *)sqlite3_column_text(stmt, 1);
            if (name) [cols addObject:[NSString stringWithUTF8String:name]];
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return cols;
}

// 某 service 在当前设备 TCC 中是否被使用（避免给不存在的 service 造无效行）
static BOOL PM_serviceInUse(NSString *svc) {
    BOOL used = NO;
    sqlite3 *db = PM_openTCC();
    if (!db) return NO;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM access WHERE service=? LIMIT 1", -1, &s, NULL) == SQLITE_OK) {
        sqlite3_bind_text(s, 1, [svc UTF8String], -1, SQLITE_TRANSIENT);
        if (sqlite3_step(s) == SQLITE_ROW) used = YES;
    }
    sqlite3_finalize(s);
    sqlite3_close(db);
    return used;
}

// 读取某 client 在某 service 的 auth_value：-1 未知
static NSInteger PM_status(NSString *svc, NSString *client) {
    NSInteger r = -1;
    sqlite3 *db = PM_openTCC();
    if (!db) return r;
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT auth_value FROM access WHERE service=? AND client=?";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, [svc UTF8String], -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, [client UTF8String], -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) r = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return r;
}

// 读取某 App 某权限的聚合状态（任一候选 service 允许即视为允许）
static NSInteger PM_permStatus(NSInteger p, NSString *client) {
    NSInteger result = -1;
    for (NSString *svc in PM_permServices(p)) {
        NSInteger s = PM_status(svc, client);
        if (s == 2 || s == 3) { result = 2; break; }   // 允许/受限 -> 视为开
        if (s == 0) result = 0;                          // 拒绝
    }
    return result;
}

// 计算目标 App 的 code requirement（csreq），让系统认可授权。
// 关键：Security 私有符号全部用 dlsym 运行时解析，绝不作为导入符号留在 dylib 里。
static NSData *PM_csreq(NSString *bundlePath) {
    if (!bundlePath.length) return nil;
    @try {
        static void *secHandle = NULL;
        static OSStatus (*pSecStaticCodeCreateWithPath)(CFURLRef, SecCSFlags, SecStaticCodeRef *) = NULL;
        static OSStatus (*pSecCodeCopyRequirements)(SecStaticCodeRef, SecCSFlags, SecRequirementRef *) = NULL;
        static OSStatus (*pSecRequirementCopyData)(SecRequirementRef, SecCSFlags, CFDataRef *) = NULL;
        static dispatch_once_t once;
        dispatch_once(&once, ^{
            secHandle = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);
            if (secHandle) {
                pSecStaticCodeCreateWithPath = dlsym(secHandle, "SecStaticCodeCreateWithPath");
                pSecCodeCopyRequirements     = dlsym(secHandle, "SecCodeCopyRequirements");
                pSecRequirementCopyData      = dlsym(secHandle, "SecRequirementCopyData");
            }
        });
        if (!pSecStaticCodeCreateWithPath || !pSecCodeCopyRequirements || !pSecRequirementCopyData)
            return nil;
        NSURL *url = [NSURL fileURLWithPath:bundlePath];
        SecStaticCodeRef sc = NULL;
        if (pSecStaticCodeCreateWithPath((__bridge CFURLRef)url, kSecCSDefaultFlags, &sc) != errSecSuccess || !sc)
            return nil;
        SecRequirementRef req = NULL;
        NSData *out = nil;
        if (pSecCodeCopyRequirements(sc, kSecCSRequirementInformation, &req) == errSecSuccess && req) {
            CFDataRef d = NULL;
            if (pSecRequirementCopyData(req, kSecCSDefaultFlags, &d) == errSecSuccess && d)
                out = (__bridge_transfer NSData *)d;
            if (req) CFRelease(req);
        }
        if (sc) CFRelease(sc);
        return out;
    } @catch (NSException *e) {
        return nil;
    }
}

// 写入某 client/service 的 auth_value；不存在则按探测到的列 INSERT
static BOOL PM_setStatus(NSString *svc, NSString *client, NSInteger val, NSData *csreq) {
    BOOL ok = NO;
    sqlite3 *db = PM_openTCC();
    if (!db) return NO;
    @try {
        // 是否已有记录
        BOOL exists = NO;
        sqlite3_stmt *c = NULL;
        if (sqlite3_prepare_v2(db, "SELECT 1 FROM access WHERE service=? AND client=?", -1, &c, NULL) == SQLITE_OK) {
            sqlite3_bind_text(c, 1, [svc UTF8String], -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(c, 2, [client UTF8String], -1, SQLITE_TRANSIENT);
            if (sqlite3_step(c) == SQLITE_ROW) exists = YES;
        }
        sqlite3_finalize(c);

        if (exists) {
            sqlite3_stmt *s = NULL;
            if (sqlite3_prepare_v2(db, "UPDATE access SET auth_value=? WHERE service=? AND client=?", -1, &s, NULL) == SQLITE_OK) {
                sqlite3_bind_int(s, 1, (int)val);
                sqlite3_bind_text(s, 2, [svc UTF8String], -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(s, 3, [client UTF8String], -1, SQLITE_TRANSIENT);
                ok = (sqlite3_step(s) == SQLITE_DONE);
            }
            sqlite3_finalize(s);
        } else {
            NSArray *cols = PM_accessColumns();
            NSArray *names = @[@"service", @"client", @"auth_value", @"auth_reason",
                              @"auth_version", @"csreq", @"policy_id", @"last_modified", @"flag"];
            NSArray *values = @[svc, client, @(val), @(1), @(1),
                                 (csreq ?: [NSNull null]), @(0), @((long)time(NULL)), @(0)];
            NSMutableArray *vNames = [NSMutableArray array];
            NSMutableArray *vVals = [NSMutableArray array];
            for (NSUInteger i = 0; i < names.count; i++) {
                if ([cols containsObject:names[i]]) {
                    [vNames addObject:names[i]];
                    [vVals addObject:values[i]];
                }
            }
            if (vNames.count == 0) { sqlite3_close(db); return NO; }
            NSMutableArray *ph = [NSMutableArray array];
            for (NSUInteger i = 0; i < vNames.count; i++) [ph addObject:@"?"];
            NSString *sql = [NSString stringWithFormat:@"INSERT INTO access (%@) VALUES (%@)",
                             [vNames componentsJoinedByString:@","], [ph componentsJoinedByString:@","]];
            sqlite3_stmt *s = NULL;
            if (sqlite3_prepare_v2(db, [sql UTF8String], -1, &s, NULL) == SQLITE_OK) {
                for (NSUInteger i = 0; i < vVals.count; i++) {
                    id v = vVals[i];
                    if ([v isKindOfClass:[NSNull class]]) sqlite3_bind_null(s, (int)(i + 1));
                    else if ([v isKindOfClass:[NSNumber class]]) sqlite3_bind_int(s, (int)(i + 1), [v intValue]);
                    else if ([v isKindOfClass:[NSData class]]) {
                        NSData *d = (NSData *)v;
                        sqlite3_bind_blob(s, (int)(i + 1), d.bytes, (int)d.length, SQLITE_TRANSIENT);
                    } else sqlite3_bind_text(s, (int)(i + 1), [v UTF8String], -1, SQLITE_TRANSIENT);
                }
                ok = (sqlite3_step(s) == SQLITE_DONE);
            }
            sqlite3_finalize(s);
        }
    } @catch (NSException *e) {
        ok = NO;
    }
    sqlite3_close(db);
    return ok;
}

// 重置某 App 某权限：删除其在各候选 service 的 TCC 行（恢复系统默认提示）
static void PM_resetPerm(NSInteger p, NSString *client) {
    sqlite3 *db = PM_openTCC();
    if (!db) return;
    for (NSString *svc in PM_permServices(p)) {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db, "DELETE FROM access WHERE service=? AND client=?", -1, &s, NULL) == SQLITE_OK) {
            sqlite3_bind_text(s, 1, [svc UTF8String], -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s, 2, [client UTF8String], -1, SQLITE_TRANSIENT);
            sqlite3_step(s);
        }
        sqlite3_finalize(s);
    }
    sqlite3_close(db);
}

// 批量设置某 App 某权限
static void PM_applyPerm(NSInteger p, NSString *client, NSInteger val, NSData *csreq) {
    if (!PM_permIsTCC(p)) return; // 本地网络不走 TCC
    for (NSString *svc in PM_permServices(p)) {
        if (PM_serviceInUse(svc)) PM_setStatus(svc, client, val, csreq);
    }
}

// 本地网络：尽力项。写意图到自身 prefs（系统本地网络不在 TCC 内，无法保证生效）。
static NSString *PM_lnKey(NSString *client) { return [@"PM_LocalNet_" stringByAppendingString:client]; }
static NSUserDefaults *PM_selfPrefs(void) {
    static NSUserDefaults *p = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ p = [[NSUserDefaults alloc] initWithSuiteName:@"com.ntm.privacymanager"]; });
    return p;
}
static NSInteger PM_lnStatus(NSString *client) {
    return [PM_selfPrefs() boolForKey:PM_lnKey(client)] ? 2 : 0;
}
static void PM_lnSet(NSString *client, BOOL on) {
    [PM_selfPrefs() setBool:on forKey:PM_lnKey(client)];
    [PM_selfPrefs() synchronize];
}

#pragma mark - App 名称解析（best-effort 文件系统扫描，仅用于显示名；枚举主源仍是 TCC.db）
static NSDictionary *PM_nameMap(void) {
    NSMutableDictionary *m = [NSMutableDictionary dictionary];
    NSFileManager *fm = [NSFileManager defaultManager];
    void (^scan)(NSString *root) = ^(NSString *root) {
        for (NSString *d in [fm contentsOfDirectoryAtPath:root error:nil] ?: @[]) {
            NSString *base = [root stringByAppendingPathComponent:d];
            if ([d hasSuffix:@".app"]) {
                NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:[base stringByAppendingPathComponent:@"Info.plist"]];
                NSString *bid = info[@"CFBundleIdentifier"];
                if (bid.length) m[bid] = info[@"CFBundleDisplayName"] ?: info[@"CFBundleName"] ?: bid;
            } else {
                for (NSString *s in [fm contentsOfDirectoryAtPath:base error:nil] ?: @[]) {
                    if ([s hasSuffix:@".app"]) {
                        NSString *app = [base stringByAppendingPathComponent:s];
                        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:[app stringByAppendingPathComponent:@"Info.plist"]];
                        NSString *bid = info[@"CFBundleIdentifier"];
                        if (bid.length) m[bid] = info[@"CFBundleDisplayName"] ?: info[@"CFBundleName"] ?: bid;
                    }
                }
            }
        }
    };
    scan(@"/var/containers/Bundle/Application");
    scan(@"/Applications");
    return m;
}

// 枚举 App：主源是 TCC.db 的 access 表（与系统隐私面板完全一致），
// 文件系统扫描仅作补充（把尚未在 TCC 留下记录的已装 App 也列出来）。
static NSArray *PM_enumerateApps(void) {
    NSMutableDictionary *apps = [NSMutableDictionary dictionary]; // bid -> {bid, path?}

    // 1) 来自 TCC.db：所有在隐私类 service 中出现过的 client（client_type=0 即 bundle id 应用）
    NSArray *svcs = PM_privacyServices();
    NSMutableString *inList = [NSMutableString string];
    for (NSUInteger i = 0; i < svcs.count; i++) {
        [inList appendFormat:@"%@'%@'", (i ? @"," : @""), svcs[i]];
    }
    NSString *sql = [NSString stringWithFormat:
        @"SELECT DISTINCT client FROM access WHERE client_type=0 AND client IS NOT NULL AND client!='' AND service IN (%@)", inList];
    sqlite3 *db = PM_openTCC();
    if (db) {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db, [sql UTF8String], -1, &s, NULL) == SQLITE_OK) {
            while (sqlite3_step(s) == SQLITE_ROW) {
                const char *c = (const char *)sqlite3_column_text(s, 0);
                if (!c) continue;
                NSString *bid = [NSString stringWithUTF8String:c];
                if (bid.length) apps[bid] = [@{ @"bid": bid } mutableCopy];
            }
        }
        sqlite3_finalize(s);
        sqlite3_close(db);
    }

    // 2) 补充：文件系统扫描已装 App（路径仅用于计算 csreq，不影响列表正确性）
    NSDictionary *nm = PM_nameMap();
    NSFileManager *fm = [NSFileManager defaultManager];
    void (^scan)(NSString *root) = ^(NSString *root) {
        for (NSString *d in [fm contentsOfDirectoryAtPath:root error:nil] ?: @[]) {
            NSString *base = [root stringByAppendingPathComponent:d];
            NSArray *subs = [d hasSuffix:@".app"] ? @[d] : ([fm contentsOfDirectoryAtPath:base error:nil] ?: @[]);
            for (NSString *s in subs) {
                NSString *app = [s hasSuffix:@".app"] ? s : [base stringByAppendingPathComponent:s];
                if (![app hasSuffix:@".app"]) continue;
                NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:[app stringByAppendingPathComponent:@"Info.plist"]];
                NSString *bid = info[@"CFBundleIdentifier"];
                if (bid.length && !apps[bid]) apps[bid] = [@{ @"bid": bid, @"path": app } mutableCopy];
                else if (bid.length && !apps[bid][@"path"]) apps[bid][@"path"] = app;
            }
        }
    };
    scan(@"/var/containers/Bundle/Application");
    scan(@"/Applications");

    // 3) 组装最终列表（带显示名），按名称排序
    NSMutableArray *out = [NSMutableArray array];
    for (NSString *bid in apps) {
        NSMutableDictionary *a = [apps[bid] mutableCopy];
        NSString *name = nm[bid] ?: bid;
        a[@"name"] = name;
        [out addObject:a];
    }
    [out sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [a[@"name"] localizedCaseInsensitiveCompare:b[@"name"]];
    }];
    return out;
}

#pragma mark - 主控制器（原生 PSListController + PSSpecifier）
@interface PMPrincipalController : PSListController @end

@implementation PMPrincipalController {
    NSArray *_apps;
    NSMutableArray *_specs;
}

#pragma mark - PreferenceLoader / PSListController 集成桩（部分 PL 版本会调用，空实现避免 unrecognized selector）
- (void)setRootController:(id)rootController {}
- (void)setParentController:(id)parentController {}
- (void)setSpecifier:(id)specifier {}
- (void)setPreferenceLoader:(id)preferenceLoader {}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"隐私与安全性";
}

#pragma mark - 构建 specifiers（面板内容）
- (id)specifiers {
    if (!_specs) {
     @try {
        _apps = PM_enumerateApps();
        _specs = [NSMutableArray array];

        // —— 顶部：批量操作 ——
        PSSpecifier *topGroup = [PSSpecifier preferenceSpecifierNamed:@"操作"
                                                              target:self set:nil get:nil detail:nil cell:PMCellGroup edit:nil];
        [topGroup setProperty:@"列出的是系统中「隐私与安全性」出现过的全部 App。开关实时写入系统 TCC 数据库，与系统设置双向同步。本地网络为尽力项（系统不存于 TCC）。"
                       forKey:@"footerText"];
        [_specs addObject:topGroup];
        [_specs addObject:[self buttonSpec:@"全部允许" action:@selector(actAllowAll)]];
        [_specs addObject:[self buttonSpec:@"全部拒绝" action:@selector(actDenyAll)]];
        [_specs addObject:[self buttonSpec:@"导出配置" action:@selector(actExport)]];
        [_specs addObject:[self buttonSpec:@"导入配置" action:@selector(actImport)]];

        // —— 每个 App 一个分组 + 7 个权限开关 + 重置按钮 ——
        for (NSDictionary *app in _apps) {
            NSString *name = app[@"name"] ?: app[@"bid"];
            PSSpecifier *g = [PSSpecifier preferenceSpecifierNamed:name
                                                           target:self set:nil get:nil detail:nil cell:PMCellGroup edit:nil];
            [g setProperty:app[@"bid"] forKey:@"PMClient"];
            [_specs addObject:g];

            for (NSInteger p = 0; p < PMPermCount; p++) {
                PSSpecifier *sw = [PSSpecifier preferenceSpecifierNamed:PM_permName(p)
                                                               target:self
                                                                  set:@selector(pmSet:specifier:)
                                                                  get:@selector(pmGet:)
                                                               detail:nil cell:PMCellSwitch edit:nil];
                [sw setProperty:app[@"bid"] forKey:@"PMClient"];
                [sw setProperty:@(p) forKey:@"PMPerm"];
                [_specs addObject:sw];
            }

            PSSpecifier *reset = [self buttonSpec:[NSString stringWithFormat:@"重置「%@」", name]
                                           action:@selector(actReset:)];
            [reset setProperty:app[@"bid"] forKey:@"PMClient"];
            [_specs addObject:reset];
        }

        [self diag:[NSString stringWithFormat:@"[specifiers] 枚举到 %ld 个 App（主源 TCC.db）", (long)_apps.count]];
     } @catch (NSException *e) {
        [self diag:[NSString stringWithFormat:@"[specifiers EXCEPTION] %@: %@", e.name, e.reason]];
        if (!_specs) _specs = [NSMutableArray array];
     }
    }
    return _specs;
}

- (PSSpecifier *)buttonSpec:(NSString *)title action:(SEL)action {
    PSSpecifier *s = [PSSpecifier preferenceSpecifierNamed:title
                                                    target:self set:nil get:nil detail:nil cell:PMCellButton edit:nil];
    [s setAction:action];
    return s;
}

#pragma mark - 开关 getter / setter（核心：读写 TCC.db，双向同步）
- (id)pmGet:(PSSpecifier *)spec {
    NSInteger p = [[spec propertyForKey:@"PMPerm"] integerValue];
    NSString *bid = [spec propertyForKey:@"PMClient"];
    NSInteger st = (p == PMPermLocalNetwork) ? PM_lnStatus(bid) : PM_permStatus(p, bid);
    return @(st == 2 || st == 3);
}

- (void)pmSet:(id)value specifier:(PSSpecifier *)spec {
    BOOL on = [value boolValue];
    NSInteger p = [[spec propertyForKey:@"PMPerm"] integerValue];
    NSString *bid = [spec propertyForKey:@"PMClient"];
    if (p == PMPermLocalNetwork) {
        PM_lnSet(bid, on);
    } else {
        NSDictionary *app = [self appForBid:bid];
        NSData *cs = nil;
        if (app[@"path"]) cs = PM_csreq(app[@"path"]);
        PM_applyPerm(p, bid, on ? 2 : 0, cs);
    }
    // 仅刷新当前开关，立即反映写入结果
    if ([self respondsToSelector:@selector(reloadSpecifier:)]) [self reloadSpecifier:spec];
}

- (NSDictionary *)appForBid:(NSString *)bid {
    for (NSDictionary *a in _apps) if ([a[@"bid"] isEqualToString:bid]) return a;
    return nil;
}

#pragma mark - 批量 / 重置
- (void)actAllowAll { [self batchSet:YES]; }
- (void)actDenyAll  { [self batchSet:NO]; }

- (void)batchSet:(BOOL)value {
    for (NSDictionary *app in _apps) {
        NSString *bid = app[@"bid"];
        NSData *cs = app[@"path"] ? PM_csreq(app[@"path"]) : nil;
        for (NSInteger p = 0; p < PMPermCount; p++) {
            if (p == PMPermLocalNetwork) PM_lnSet(bid, value);
            else PM_applyPerm(p, bid, value ? 2 : 0, cs);
        }
    }
    if ([self respondsToSelector:@selector(reloadSpecifiers)]) [self reloadSpecifiers];
    [self toast:[NSString stringWithFormat:@"已将 %ld 个 App 的权限%@", (long)_apps.count, value ? @"全部设为允许" : @"全部设为拒绝"]];
}

- (void)actReset:(PSSpecifier *)spec {
    NSString *bid = [spec propertyForKey:@"PMClient"];
    if (!bid) return;
    for (NSInteger p = 0; p < PMPermCount; p++) {
        if (p == PMPermLocalNetwork) PM_lnSet(bid, NO);
        else PM_resetPerm(p, bid);
    }
    if ([self respondsToSelector:@selector(reloadSpecifiers)]) [self reloadSpecifiers];
    [self toast:[NSString stringWithFormat:@"已重置 %@", bid]];
}

#pragma mark - 导入 / 导出
- (void)actExport {
    NSMutableDictionary *out = [NSMutableDictionary dictionary];
    out[@"version"] = @1;
    NSMutableArray *arr = [NSMutableArray array];
    for (NSDictionary *a in _apps) {
        NSMutableDictionary *perms = [NSMutableDictionary dictionary];
        for (NSInteger p = 0; p < PMPermCount; p++) {
            NSInteger st = (p == PMPermLocalNetwork) ? PM_lnStatus(a[@"bid"]) : PM_permStatus(p, a[@"bid"]);
            perms[PM_permKey(p)] = @(st);
        }
        [arr addObject:@{ @"bid": a[@"bid"], @"name": (a[@"name"] ?: a[@"bid"]), @"perms": perms }];
    }
    out[@"apps"] = arr;
    NSError *e = nil;
    NSData *json = [NSJSONSerialization dataWithJSONObject:out options:NSJSONWritingPrettyPrinted error:&e];
    if (!json) { [self toast:[NSString stringWithFormat:@"导出失败: %@", e.localizedDescription]]; return; }
    NSString *path = @"/var/mobile/Documents/privacymanager_export.json";
    [json writeToFile:path atomically:YES];
    [self toast:[NSString stringWithFormat:@"已导出 %ld 个 App 到:\n%@", (long)arr.count, path]];
}

- (void)actImport {
    UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"导入配置"
                                                               message:@"粘贴此前导出的 JSON（覆盖当前各 App 权限）"
                                                        preferredStyle:UIAlertControllerStyleAlert];
    [ac addTextFieldWithConfigurationHandler:^(UITextField * _Nonnull tf) {
        tf.placeholder = @"粘贴 JSON...";
    }];
    [ac addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [ac addAction:[UIAlertAction actionWithTitle:@"导入" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull a){
        NSString *txt = ac.textFields.firstObject.text;
        if (!txt.length) return;
        NSData *d = [txt dataUsingEncoding:NSUTF8StringEncoding];
        NSError *err = nil;
        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:d options:0 error:&err];
        if (![json isKindOfClass:[NSDictionary class]]) { [self toast:@"JSON 解析失败"]; return; }
        NSArray *apps = json[@"apps"];
        if (![apps isKindOfClass:[NSArray class]]) { [self toast:@"格式错误"]; return; }
        NSInteger n = 0;
        for (NSDictionary *item in apps) {
            NSString *bid = item[@"bid"];
            NSDictionary *perms = item[@"perms"];
            if (![bid isKindOfClass:[NSString class]] || ![perms isKindOfClass:[NSDictionary class]]) continue;
            NSDictionary *match = [self appForBid:bid];
            NSData *cs = match && match[@"path"] ? PM_csreq(match[@"path"]) : nil;
            for (NSInteger p = 0; p < PMPermCount; p++) {
                id v = perms[PM_permKey(p)];
                if (![v isKindOfClass:[NSNumber class]]) continue;
                NSInteger st = [v integerValue];
                if (p == PMPermLocalNetwork) PM_lnSet(bid, (st == 2 || st == 3));
                else PM_applyPerm(p, bid, (st == 2 || st == 3) ? 2 : 0, cs);
                n++;
            }
        }
        if ([self respondsToSelector:@selector(reloadSpecifiers)]) [self reloadSpecifiers];
        [self toast:[NSString stringWithFormat:@"已导入 %ld 条权限设置", (long)n]];
    }]];
    [self presentViewController:ac animated:YES completion:nil];
}

#pragma mark - 诊断 / 提示
- (void)diag:(NSString *)msg {
    @try {
        NSString *path = @"/var/mobile/Documents/privacymanager_diag.log";
        NSString *old = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
        NSString *entry = [NSString stringWithFormat:@"%@%@\n", (old ?: @""), msg];
        [entry writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
    } @catch (NSException *e) {}
}

- (void)toast:(NSString *)msg {
    UIAlertController *ac = [UIAlertController alertControllerWithTitle:nil message:msg
                                                        preferredStyle:UIAlertControllerStyleAlert];
    [self presentViewController:ac animated:YES completion:^{
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.2 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ [ac dismissViewControllerAnimated:YES completion:nil]; });
    }];
}

@end

#pragma mark - 真机诊断（dylib 一被加载即记录，用于定位“设置无入口”根因）
__attribute__((constructor))
static void PM_diagnose_load(void) {
    @autoreleasepool {
        @try {
            NSString *path = @"/var/mobile/Documents/privacymanager_diag.log";
            NSMutableString *log = [NSMutableString string];
            [log appendFormat:@"=== PrivacyManager dylib 加载诊断 @ %@ ===\n", [NSDate date]];
            Class c = NSClassFromString(@"PMPrincipalController");
            [log appendFormat:@"PMPrincipalController 已注册: %@\n", c ? @"YES" : @"NO"];
            Class psl = NSClassFromString(@"PSListController");
            [log appendFormat:@"PSListController 存在: %@\n", psl ? @"YES" : @"NO"];
            void *sym = dlsym(RTLD_DEFAULT, "OBJC_CLASS_$_PSSpecifier");
            [log appendFormat:@"OBJC_CLASS_$_PSSpecifier: %p\n", sym];
            NSFileManager *fm = [NSFileManager defaultManager];
            if ([fm fileExistsAtPath:kTCCDBPath]) {
                [log appendFormat:@"TCC.db 存在: YES\n"];
                sqlite3 *db = PM_openTCC();
                if (db) {
                    sqlite3_stmt *s = NULL;
                    // 安全拼接带引号的 IN 列表
                    NSMutableString *inL = [NSMutableString string];
                    NSArray *psv = PM_privacyServices();
                    for (NSUInteger i = 0; i < psv.count; i++)
                        [inL appendFormat:@"%@'%@'", (i ? @"," : @""), psv[i]];
                    NSString *chk = [NSString stringWithFormat:
                        @"SELECT COUNT(DISTINCT client) FROM access WHERE client_type=0 AND service IN (%@)", inL];
                    if (sqlite3_prepare_v2(db, [chk UTF8String], -1, &s, NULL) == SQLITE_OK) {
                        if (sqlite3_step(s) == SQLITE_ROW)
                            [log appendFormat:@"TCC.db 中隐私类 App 数: %d\n", sqlite3_column_int(s, 0)];
                    }
                    sqlite3_finalize(s);
                    sqlite3_close(db);
                } else {
                    [log appendFormat:@"TCC.db 打开失败\n"];
                }
            } else {
                [log appendFormat:@"TCC.db 不存在!\n"];
            }
            [log writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
        } @catch (NSException *e) {}
    }
}
