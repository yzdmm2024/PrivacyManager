// PrivacyManager.m — 隐私与安全性 设置面板（自定义 UITableView 卡片式 UI）
//
// 设计目标：成为系统「设置 → 隐私与安全性」的实时镜像。
//   - App 列表来自系统真相源 /var/mobile/Library/TCC/TCC.db（与系统面板一致）
//   - 每个 App 的 7 类权限开关直接读写同一个 TCC.db（你开他就开 你关他就关，双向同步）
// 运行于 Settings.app 进程（platform-application，已脱离沙盒），可直读写 TCC.db。
//
// UI 架构参考同机正常工作的「通知管理」插件：PSViewController + 自绘 UITableView，
// 每个 App 一张卡片（图标 + 名称 + 重置 + 总开关 + 横排权限开关），浅色玻璃风格。
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

#pragma mark - 前向声明
// PSViewController 是 PreferenceLoader 控制器的正确基类（实现 PSController 协议），
// 提供 setSpecifier:/setParentController:/setRootController: 等集成方法，避免
// controllerForSpecifier: 调用未实现方法导致 unrecognized selector 崩溃。
@interface PSViewController : UIViewController @end

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
// 多候选路径探测：iOS 各版本/越狱形态下 TCC.db 位置可能不同
static NSString *PM_tccPath(void) {
    NSArray *cands = @[
        @"/var/mobile/Library/TCC/TCC.db",
        @"/private/var/mobile/Library/TCC/TCC.db",
    ];
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *p in cands) {
        if ([fm fileExistsAtPath:p]) return p;
    }
    return cands[0];
}

static sqlite3 *PM_openTCC(void) {
    sqlite3 *db = NULL;
    NSString *path = PM_tccPath();
    if (sqlite3_open([path UTF8String], &db) != SQLITE_OK) {
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
            NSArray *names = @[@"service", @"client", @"client_type", @"auth_value", @"auth_reason",
                              @"auth_version", @"csreq", @"policy_id", @"last_modified", @"flag"];
            NSArray *values = @[svc, client, @0, @(val), @(1), @(1),
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

// 批量设置某 App 某权限（每个候选 service 都写，确保授权真正生效）
static void PM_applyPerm(NSInteger p, NSString *client, NSInteger val, NSData *csreq) {
    if (!PM_permIsTCC(p)) return; // 本地网络不走 TCC
    for (NSString *svc in PM_permServices(p)) {
        PM_setStatus(svc, client, val, csreq);
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

    // 1) 来自 TCC.db：所有在隐私类 service 中出现过的 client
    NSArray *svcs = PM_privacyServices();
    NSMutableString *inList = [NSMutableString string];
    for (NSUInteger i = 0; i < svcs.count; i++) {
        [inList appendFormat:@"%@'%@'", (i ? @"," : @""), svcs[i]];
    }
    NSArray *queries = @[
        [NSString stringWithFormat:@"SELECT DISTINCT client FROM access WHERE client_type=0 AND client IS NOT NULL AND client!='' AND service IN (%@)", inList],
        [NSString stringWithFormat:@"SELECT DISTINCT client FROM access WHERE client IS NOT NULL AND client!='' AND service IN (%@)", inList],
    ];
    sqlite3 *db = PM_openTCC();
    if (db) {
        for (NSString *q in queries) {
            sqlite3_stmt *s = NULL;
            if (sqlite3_prepare_v2(db, [q UTF8String], -1, &s, NULL) == SQLITE_OK) {
                while (sqlite3_step(s) == SQLITE_ROW) {
                    const char *c = (const char *)sqlite3_column_text(s, 0);
                    if (!c) continue;
                    NSString *bid = [NSString stringWithUTF8String:c];
                    if (bid.length) apps[bid] = [@{ @"bid": bid } mutableCopy];
                }
            }
            sqlite3_finalize(s);
            if (apps.count > 0) break;
        }
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

// 把某 App 当前 7 类权限状态填入其字典的 perms 数组（后台线程调用，避免首次进入卡顿）
static void PM_fillPerms(NSMutableDictionary *app) {
    if (!app) return;
    NSMutableArray *perms = [NSMutableArray array];
    NSString *bid = app[@"bid"];
    for (NSInteger p = 0; p < PMPermCount; p++) {
        NSInteger st = (p == PMPermLocalNetwork) ? PM_lnStatus(bid) : PM_permStatus(p, bid);
        [perms addObject:@(st)];
    }
    app[@"perms"] = perms;
}

#pragma mark - App 卡片视图（仿通知管理 NTMAppCardView）
@interface PMPermCardView : UIView
@property (nonatomic, strong) NSMutableDictionary *app;
@property (nonatomic, strong) UIImageView *iconView;
@property (nonatomic, strong) UISwitch *masterSwitch;
@property (nonatomic, strong) NSMutableArray<UISwitch *> *permSwitches;
@property (nonatomic, copy) void (^onChange)(NSString *appId);
- (instancetype)initWithApp:(NSMutableDictionary *)app;
- (void)reloadFromModel;
@end

@implementation PMPermCardView

- (instancetype)initWithApp:(NSMutableDictionary *)app {
    self = [super init];
    if (self) {
        _app = app;
        _permSwitches = [NSMutableArray array];
        [self buildUI];
    }
    return self;
}

- (void)buildUI {
    self.backgroundColor = [UIColor colorWithWhite:0.98 alpha:0.92];
    self.layer.cornerRadius = 18;
    self.layer.masksToBounds = NO;
    self.layer.shadowColor = [UIColor colorWithWhite:0 alpha:0.08].CGColor;
    self.layer.shadowOpacity = 1;
    self.layer.shadowRadius = 12;
    self.layer.shadowOffset = CGSizeMake(0, 4);

    // ── 头部行：图标 + 名称 + 重置 + 总开关 ──
    _iconView = [[UIImageView alloc] init];
    _iconView.contentMode = UIViewContentModeScaleAspectFill;
    _iconView.layer.cornerRadius = 9;
    _iconView.clipsToBounds = YES;
    _iconView.backgroundColor = [UIColor colorWithRed:0.88 green:0.90 blue:0.95 alpha:1];
    [_iconView.widthAnchor constraintEqualToConstant:36].active = YES;
    [_iconView.heightAnchor constraintEqualToConstant:36].active = YES;
    [self loadIconAsync];

    UILabel *nameLabel = [[UILabel alloc] init];
    nameLabel.text = _app[@"name"] ?: _app[@"bid"];
    nameLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightSemibold];
    nameLabel.textColor = [UIColor colorWithWhite:0.12 alpha:1];
    [nameLabel setContentHuggingPriority:UILayoutPriorityDefaultLow forAxis:UILayoutConstraintAxisHorizontal];
    [nameLabel setContentCompressionResistancePriority:UILayoutPriorityDefaultLow forAxis:UILayoutConstraintAxisHorizontal];

    UIButton *resetBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    [resetBtn setTitle:@"重置" forState:UIControlStateNormal];
    [resetBtn setTitleColor:[UIColor colorWithRed:0.78 green:0.28 blue:0.28 alpha:1] forState:UIControlStateNormal];
    resetBtn.titleLabel.font = [UIFont systemFontOfSize:12 weight:UIFontWeightBold];
    [resetBtn addTarget:self action:@selector(resetTapped) forControlEvents:UIControlEventTouchUpInside];

    UILabel *masterLabel = [[UILabel alloc] init];
    masterLabel.text = @"总开关";
    masterLabel.font = [UIFont systemFontOfSize:12 weight:UIFontWeightMedium];
    masterLabel.textColor = [UIColor colorWithWhite:0.40 alpha:1];

    _masterSwitch = [[UISwitch alloc] init];
    _masterSwitch.onTintColor = [UIColor colorWithRed:0.32 green:0.68 blue:0.88 alpha:1];
    [_masterSwitch addTarget:self action:@selector(masterChanged) forControlEvents:UIControlEventValueChanged];

    UIStackView *header = [[UIStackView alloc] initWithArrangedSubviews:@[_iconView, nameLabel, resetBtn, masterLabel, _masterSwitch]];
    header.axis = UILayoutConstraintAxisHorizontal;
    header.alignment = UIStackViewAlignmentCenter;
    header.spacing = 10;

    // ── 权限开关行：7 个权限横排 ──
    NSMutableArray *permItems = [NSMutableArray array];
    for (NSInteger p = 0; p < PMPermCount; p++) {
        UILabel *lbl = [[UILabel alloc] init];
        lbl.text = PM_permName(p);
        lbl.font = [UIFont systemFontOfSize:10];
        lbl.textColor = [UIColor colorWithWhite:0.35 alpha:1];
        lbl.textAlignment = NSTextAlignmentCenter;

        UISwitch *sw = [[UISwitch alloc] init];
        sw.transform = CGAffineTransformMakeScale(0.66, 0.66);
        sw.onTintColor = [UIColor colorWithRed:0.32 green:0.68 blue:0.88 alpha:1];
        [sw addTarget:self action:@selector(permChanged:) forControlEvents:UIControlEventValueChanged];
        [_permSwitches addObject:sw];

        UIStackView *item = [[UIStackView alloc] initWithArrangedSubviews:@[lbl, sw]];
        item.axis = UILayoutConstraintAxisVertical;
        item.alignment = UIStackViewAlignmentCenter;
        item.spacing = 2;
        [permItems addObject:item];
    }
    UIStackView *permRow = [[UIStackView alloc] initWithArrangedSubviews:permItems];
    permRow.axis = UILayoutConstraintAxisHorizontal;
    permRow.distribution = UIStackViewDistributionFillEqually;
    permRow.alignment = UIStackViewAlignmentCenter;
    permRow.spacing = 4;

    // ── 垂直堆叠 ──
    UIStackView *v = [[UIStackView alloc] initWithArrangedSubviews:@[header, permRow]];
    v.axis = UILayoutConstraintAxisVertical;
    v.spacing = 12;
    v.translatesAutoresizingMaskIntoConstraints = NO;
    [self addSubview:v];
    [NSLayoutConstraint activateConstraints:@[
        [v.topAnchor constraintEqualToAnchor:self.topAnchor constant:14],
        [v.leadingAnchor constraintEqualToAnchor:self.leadingAnchor constant:14],
        [v.trailingAnchor constraintEqualToAnchor:self.trailingAnchor constant:-14],
        [v.bottomAnchor constraintEqualToAnchor:self.bottomAnchor constant:-14],
    ]];

    [self reloadFromModel];
}

- (void)loadIconAsync {
    NSString *bid = _app[@"bid"];
    if (!bid.length) return;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        UIImage *icon = nil;
        @try {
            id (*f)(id, SEL, id, long long, double) = (id (*)(id, SEL, id, long long, double))objc_msgSend;
            icon = f((id)UIImage.class,
                     sel_registerName("_applicationIconImageForBundleIdentifier:format:scale:"),
                     bid, 0, 2.0);
        } @catch (NSException *e) {}
        if (icon && [icon isKindOfClass:UIImage.class]) {
            dispatch_async(dispatch_get_main_queue(), ^{ self.iconView.image = icon; });
        }
    });
}

- (void)masterChanged {
    BOOL on = _masterSwitch.on;
    NSString *bid = _app[@"bid"];
    NSData *cs = _app[@"path"] ? PM_csreq(_app[@"path"]) : nil;
    for (NSInteger p = 0; p < PMPermCount; p++) {
        if (p == PMPermLocalNetwork) PM_lnSet(bid, on);
        else PM_applyPerm(p, bid, on ? 2 : 0, cs);
    }
    [self reloadFromModel];
    if (_onChange) _onChange(bid);
}

- (void)permChanged:(UISwitch *)sender {
    NSUInteger idx = [_permSwitches indexOfObject:sender];
    if (idx == NSNotFound || idx >= PMPermCount) return;
    BOOL on = sender.on;
    NSString *bid = _app[@"bid"];
    NSData *cs = _app[@"path"] ? PM_csreq(_app[@"path"]) : nil;
    if (idx == PMPermLocalNetwork) PM_lnSet(bid, on);
    else PM_applyPerm((NSInteger)idx, bid, on ? 2 : 0, cs);
    [self reloadFromModel];
    if (_onChange) _onChange(bid);
}

- (void)resetTapped {
    NSString *bid = _app[@"bid"];
    for (NSInteger p = 0; p < PMPermCount; p++) {
        if (p == PMPermLocalNetwork) PM_lnSet(bid, NO);
        else PM_resetPerm(p, bid);
    }
    [self reloadFromModel];
    if (_onChange) _onChange(bid);
}

- (void)reloadFromModel {
    NSArray *perms = _app[@"perms"];
    if (!perms || perms.count != PMPermCount) PM_fillPerms(_app);
    perms = _app[@"perms"];
    BOOL allOn = YES;
    for (NSInteger p = 0; p < PMPermCount; p++) {
        NSInteger st = (perms && p < perms.count) ? [perms[p] integerValue] : -1;
        BOOL on = (st == 2 || st == 3);
        if (p < _permSwitches.count) _permSwitches[p].on = on;
        if (!on) allOn = NO;
    }
    _masterSwitch.on = allOn;
}

@end

#pragma mark - 主控制器（PSViewController + 自绘 UITableView，仿通知管理）
@interface PMPrincipalController : PSViewController <UISearchBarDelegate, UITableViewDelegate, UITableViewDataSource>
@end

@implementation PMPrincipalController {
    UISearchBar *_searchBar;
    UILabel *_statLabel;
    UITableView *_tableView;
    UIActivityIndicatorView *_spinner;
    NSArray *_allApps;   // NSMutableDictionary 数组（含 perms）
    NSArray *_curApps;
    NSString *_searchText;
}

// PreferenceLoader/PSListController 集成方法（自定义 UI 不使用，仅避免 unrecognized selector 崩溃）
- (void)setRootController:(id)rootController {}
- (void)setParentController:(id)parentController {}
- (void)setSpecifier:(id)specifier {}
- (void)setPreferenceLoader:(id)preferenceLoader {}
- (void)setParentController:(id)parentController specifier:(id)specifier {}

static UIButton *PM_pillButton(NSString *title, UIColor *bg, UIColor *fg) {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    [b setTitle:title forState:UIControlStateNormal];
    [b setTitleColor:fg forState:UIControlStateNormal];
    b.titleLabel.font = [UIFont systemFontOfSize:14 weight:UIFontWeightSemibold];
    b.backgroundColor = bg;
    b.layer.cornerRadius = 14;
    b.clipsToBounds = YES;
    return b;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"隐私与安全性";
    self.overrideUserInterfaceStyle = UIUserInterfaceStyleLight;
    self.view.backgroundColor = [UIColor colorWithRed:0.95 green:0.96 blue:0.98 alpha:1];
    _searchText = @"";

    [self buildUI];

    _spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    _spinner.translatesAutoresizingMaskIntoConstraints = NO;
    [_spinner startAnimating];
    [self.view addSubview:_spinner];
    [NSLayoutConstraint activateConstraints:@[
        [_spinner.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [_spinner.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor],
    ]];

    // 异步枚举 App + 预读权限状态，避免进入面板卡顿
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSArray *apps = PM_enumerateApps();
        for (NSMutableDictionary *a in apps) PM_fillPerms(a);
        dispatch_async(dispatch_get_main_queue(), ^{
            _allApps = apps;
            [self reloadList];
        });
    });
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    // 回到面板时从 TCC 重新同步（系统在别处改了权限也能反映）
    if (_allApps.count) {
        for (NSMutableDictionary *a in _allApps) PM_fillPerms(a);
        [self reloadList];
    }
}

- (void)buildUI {
    // 批量操作：全部允许 / 全部拒绝
    UIButton *allowAll = PM_pillButton(@"全部允许",
        [UIColor colorWithRed:0.45 green:0.78 blue:0.54 alpha:0.18],
        [UIColor colorWithRed:0.13 green:0.55 blue:0.24 alpha:1]);
    [allowAll addTarget:self action:@selector(allowAllTapped) forControlEvents:UIControlEventTouchUpInside];

    UIButton *denyAll = PM_pillButton(@"全部拒绝",
        [UIColor colorWithRed:0.87 green:0.24 blue:0.24 alpha:0.15],
        [UIColor colorWithRed:0.72 green:0.17 blue:0.17 alpha:1]);
    [denyAll addTarget:self action:@selector(denyAllTapped) forControlEvents:UIControlEventTouchUpInside];

    UIStackView *batchRow = [[UIStackView alloc] initWithArrangedSubviews:@[allowAll, denyAll]];
    batchRow.axis = UILayoutConstraintAxisHorizontal;
    batchRow.distribution = UIStackViewDistributionFillEqually;
    batchRow.spacing = 10;

    _statLabel = [[UILabel alloc] init];
    _statLabel.font = [UIFont systemFontOfSize:12];
    _statLabel.textColor = [UIColor colorWithWhite:0.4 alpha:1];

    _searchBar = [[UISearchBar alloc] init];
    _searchBar.placeholder = @"搜索应用名称或 Bundle ID";
    _searchBar.delegate = self;
    _searchBar.searchBarStyle = UISearchBarStyleMinimal;
    _searchBar.backgroundImage = [UIImage new];

    _tableView = [[UITableView alloc] initWithFrame:CGRectZero style:UITableViewStylePlain];
    _tableView.delegate = self;
    _tableView.dataSource = self;
    _tableView.separatorStyle = UITableViewCellSeparatorStyleNone;
    _tableView.backgroundColor = [UIColor clearColor];
    _tableView.keyboardDismissMode = UIScrollViewKeyboardDismissModeOnDrag;
    _tableView.contentInset = UIEdgeInsetsMake(4, 0, 80, 0);

    UIButton *exportBtn = PM_pillButton(@"导出配置",
        [UIColor colorWithRed:0.35 green:0.56 blue:1.0 alpha:0.15],
        [UIColor colorWithRed:0.17 green:0.35 blue:0.72 alpha:1]);
    [exportBtn addTarget:self action:@selector(exportConfig) forControlEvents:UIControlEventTouchUpInside];

    UIButton *importBtn = PM_pillButton(@"导入配置",
        [UIColor colorWithRed:0.45 green:0.78 blue:0.54 alpha:0.18],
        [UIColor colorWithRed:0.13 green:0.55 blue:0.24 alpha:1]);
    [importBtn addTarget:self action:@selector(importConfig) forControlEvents:UIControlEventTouchUpInside];

    UIView *bottomBar = [[UIView alloc] init];
    bottomBar.backgroundColor = [UIColor colorWithWhite:0.97 alpha:0.95];
    bottomBar.translatesAutoresizingMaskIntoConstraints = NO;
    UIStackView *bottomRow = [[UIStackView alloc] initWithArrangedSubviews:@[exportBtn, importBtn]];
    bottomRow.axis = UILayoutConstraintAxisHorizontal;
    bottomRow.distribution = UIStackViewDistributionFillEqually;
    bottomRow.spacing = 12;
    bottomRow.translatesAutoresizingMaskIntoConstraints = NO;
    [bottomBar addSubview:bottomRow];
    [NSLayoutConstraint activateConstraints:@[
        [bottomRow.topAnchor constraintEqualToAnchor:bottomBar.topAnchor constant:8],
        [bottomRow.leadingAnchor constraintEqualToAnchor:bottomBar.leadingAnchor constant:16],
        [bottomRow.trailingAnchor constraintEqualToAnchor:bottomBar.trailingAnchor constant:-16],
        [bottomRow.bottomAnchor constraintEqualToAnchor:bottomBar.bottomAnchor constant:-8],
    ]];

    for (UIView *v in @[_tableView, batchRow, _statLabel, _searchBar, bottomBar]) {
        v.translatesAutoresizingMaskIntoConstraints = NO;
        [self.view addSubview:v];
    }

    [NSLayoutConstraint activateConstraints:@[
        [batchRow.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor constant:12],
        [batchRow.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:16],
        [batchRow.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-16],
        [batchRow.heightAnchor constraintEqualToConstant:40],

        [_statLabel.topAnchor constraintEqualToAnchor:batchRow.bottomAnchor constant:8],
        [_statLabel.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:20],
        [_statLabel.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-20],

        [_searchBar.topAnchor constraintEqualToAnchor:_statLabel.bottomAnchor constant:2],
        [_searchBar.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:8],
        [_searchBar.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-8],

        [_tableView.topAnchor constraintEqualToAnchor:_searchBar.bottomAnchor constant:6],
        [_tableView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [_tableView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [_tableView.bottomAnchor constraintEqualToAnchor:bottomBar.topAnchor constant:-4],

        [bottomBar.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [bottomBar.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [bottomBar.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],
    ]];
}

- (void)hideSpinner {
    if (_spinner) { [_spinner stopAnimating]; [_spinner removeFromSuperview]; _spinner = nil; }
}

#pragma mark - UITableViewDataSource
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return _curApps.count;
}
- (CGFloat)tableView:(UITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath {
    return 132;
}
- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"card"];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:@"card"];
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        cell.backgroundColor = [UIColor clearColor];
    }
    for (UIView *v in cell.contentView.subviews) [v removeFromSuperview];

    NSMutableDictionary *app = _curApps[indexPath.row];
    PMPermCardView *card = [[PMPermCardView alloc] initWithApp:app];
    card.translatesAutoresizingMaskIntoConstraints = NO;
    __weak typeof(self) ws = self;
    card.onChange = ^(NSString *aid) { [ws refreshStat]; };
    [cell.contentView addSubview:card];
    [NSLayoutConstraint activateConstraints:@[
        [card.topAnchor constraintEqualToAnchor:cell.contentView.topAnchor constant:6],
        [card.leadingAnchor constraintEqualToAnchor:cell.contentView.leadingAnchor constant:16],
        [card.trailingAnchor constraintEqualToAnchor:cell.contentView.trailingAnchor constant:-16],
        [card.bottomAnchor constraintEqualToAnchor:cell.contentView.bottomAnchor constant:-6],
    ]];
    return cell;
}

#pragma mark - 列表
- (void)reloadList {
    NSMutableArray *filtered = [NSMutableArray array];
    for (NSMutableDictionary *app in _allApps) {
        if (_searchText.length) {
            NSString *name = app[@"name"];
            NSString *bid = app[@"bid"];
            if (![name localizedCaseInsensitiveContainsString:_searchText] &&
                ![bid localizedCaseInsensitiveContainsString:_searchText]) continue;
        }
        [filtered addObject:app];
    }
    _curApps = filtered;

    if (!filtered.count) {
        UILabel *empty = [[UILabel alloc] initWithFrame:CGRectMake(0, 0, 260, 80)];
        empty.text = _allApps.count ? @"没有匹配的应用" : @"暂无应用（TCC 中无隐私类记录）";
        empty.font = [UIFont systemFontOfSize:14];
        empty.textColor = [UIColor colorWithWhite:0.55 alpha:1];
        empty.textAlignment = NSTextAlignmentCenter;
        _tableView.backgroundView = empty;
    } else {
        _tableView.backgroundView = nil;
    }

    [_tableView reloadData];
    [self refreshStat];
    [self hideSpinner];
}

- (void)refreshAllCards {
    for (UITableViewCell *cell in _tableView.visibleCells) {
        for (UIView *v in cell.contentView.subviews) {
            if ([v isKindOfClass:[PMPermCardView class]]) [(PMPermCardView *)v reloadFromModel];
        }
    }
}

- (void)refreshStat {
    NSInteger total = 0, on = 0;
    for (NSDictionary *app in _curApps) {
        NSArray *perms = app[@"perms"];
        BOOL all = YES;
        for (NSInteger p = 0; p < PMPermCount; p++) {
            NSInteger st = (perms && p < perms.count) ? [perms[p] integerValue] : -1;
            if (!(st == 2 || st == 3)) { all = NO; break; }
        }
        if (all) on++;
        total++;
    }
    NSString *scope = _searchText.length ? [NSString stringWithFormat:@"搜索：%@", _searchText] : @"全部应用";
    _statLabel.text = [NSString stringWithFormat:@"%@    已全开 %ld / %ld 个应用", scope, (long)on, (long)total];
}

#pragma mark - 批量
- (void)allowAllTapped { [self batchWrite:YES]; }
- (void)denyAllTapped  { [self batchWrite:NO]; }

- (void)batchWrite:(BOOL)val {
    for (NSMutableDictionary *app in _allApps) {
        NSString *bid = app[@"bid"];
        NSData *cs = app[@"path"] ? PM_csreq(app[@"path"]) : nil;
        NSMutableArray *perms = app[@"perms"];
        if (![perms isKindOfClass:[NSMutableArray class]]) { perms = [NSMutableArray array]; app[@"perms"] = perms; }
        for (NSInteger p = 0; p < PMPermCount; p++) {
            if (p == PMPermLocalNetwork) PM_lnSet(bid, val);
            else PM_applyPerm(p, bid, val ? 2 : 0, cs);
            if (p < perms.count) perms[p] = @(val ? 2 : 0);
            else [perms addObject:@(val ? 2 : 0)];
        }
    }
    [self refreshAllCards];
    [self refreshStat];
    [self toast:[NSString stringWithFormat:@"已将 %ld 个应用权限%@", (long)_allApps.count, val ? @"全部允许" : @"全部拒绝"]];
}

#pragma mark - 导入 / 导出
- (void)exportConfig {
    NSMutableArray *arr = [NSMutableArray array];
    for (NSDictionary *app in _allApps) {
        [arr addObject:@{ @"bid": app[@"bid"], @"name": (app[@"name"] ?: app[@"bid"]), @"perms": (app[@"perms"] ?: @[]) }];
    }
    NSData *data = [NSJSONSerialization dataWithJSONObject:arr options:NSJSONWritingPrettyPrinted error:nil];
    if (!data) { [self toast:@"导出失败"]; return; }
    NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/PrivacyManagerConfig.json"];
    if (![data writeToFile:path atomically:YES]) { [self toast:@"导出失败，无写入权限"]; return; }
    NSURL *url = [NSURL fileURLWithPath:path];
    UIActivityViewController *avc = [[UIActivityViewController alloc] initWithActivityItems:@[url] applicationActivities:nil];
    avc.popoverPresentationController.sourceView = self.view;
    avc.popoverPresentationController.sourceRect = CGRectMake(self.view.bounds.size.width/2, self.view.bounds.size.height, 1, 1);
    [self presentViewController:avc animated:YES completion:nil];
}

- (void)importConfig {
    UIDocumentPickerViewController *picker = [[UIDocumentPickerViewController alloc]
        initWithDocumentTypes:@[@"public.json", @"public.data"] inMode:UIDocumentPickerModeImport];
    picker.delegate = self;
    [self presentViewController:picker animated:YES completion:nil];
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    NSURL *url = urls.firstObject;
    if (!url) return;
    NSData *data = [NSData dataWithContentsOfURL:url];
    if (!data) { [self toast:@"读取文件失败"]; return; }
    NSArray *arr = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if (![arr isKindOfClass:[NSArray class]]) { [self toast:@"配置格式错误"]; return; }
    NSInteger count = 0;
    for (NSDictionary *item in arr) {
        NSString *bid = item[@"bid"];
        NSArray *perms = item[@"perms"];
        if (![bid isKindOfClass:[NSString class]] || ![perms isKindOfClass:[NSArray class]]) continue;
        NSDictionary *match = nil;
        for (NSMutableDictionary *a in _allApps) if ([a[@"bid"] isEqualToString:bid]) { match = a; break; }
        if (!match) continue;
        NSData *cs = match[@"path"] ? PM_csreq(match[@"path"]) : nil;
        NSMutableArray *mperms = [NSMutableArray array];
        for (NSInteger p = 0; p < PMPermCount; p++) {
            NSInteger st = (p < perms.count) ? [perms[p] integerValue] : -1;
            BOOL on = (st == 2 || st == 3);
            if (p == PMPermLocalNetwork) PM_lnSet(bid, on);
            else PM_applyPerm(p, bid, on ? 2 : 0, cs);
            [mperms addObject:@(on ? 2 : 0)];
        }
        match[@"perms"] = mperms;
        count++;
    }
    [self refreshAllCards];
    [self refreshStat];
    [self toast:[NSString stringWithFormat:@"已导入 %ld 个应用", (long)count]];
}

#pragma mark - 搜索（防抖 0.3s）
- (void)searchBar:(UISearchBar *)searchBar textDidChange:(NSString *)searchText {
    _searchText = searchText ?: @"";
    [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(applySearch) object:nil];
    [self performSelector:@selector(applySearch) withObject:nil afterDelay:0.3];
}
- (void)applySearch { [self reloadList]; }
- (void)searchBarSearchButtonClicked:(UISearchBar *)searchBar {
    [searchBar resignFirstResponder];
    [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(applySearch) object:nil];
    [self applySearch];
}

#pragma mark - 诊断 / Toast
- (void)diag:(NSString *)msg {
    @try {
        NSString *path = @"/var/mobile/Documents/privacymanager_diag.log";
        NSString *old = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
        NSString *entry = [NSString stringWithFormat:@"%@%@\n", (old ?: @""), msg];
        [entry writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
    } @catch (NSException *e) {}
}

- (void)toast:(NSString *)msg {
    UILabel *l = [[UILabel alloc] init];
    l.text = msg;
    l.font = [UIFont systemFontOfSize:13];
    l.textColor = [UIColor whiteColor];
    l.backgroundColor = [UIColor colorWithWhite:0 alpha:0.78];
    l.layer.cornerRadius = 10;
    l.clipsToBounds = YES;
    l.textAlignment = NSTextAlignmentCenter;
    l.numberOfLines = 0;
    l.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:l];
    [NSLayoutConstraint activateConstraints:@[
        [l.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [l.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor],
        [l.leadingAnchor constraintGreaterThanOrEqualToAnchor:self.view.leadingAnchor constant:30],
        [l.trailingAnchor constraintLessThanOrEqualToAnchor:self.view.trailingAnchor constant:-30],
    ]];
    l.alpha = 0;
    [UIView animateWithDuration:0.2 animations:^{ l.alpha = 1; }];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [UIView animateWithDuration:0.3 animations:^{ l.alpha = 0; } completion:^(BOOL f){ [l removeFromSuperview]; }];
    });
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
            NSFileManager *fm = [NSFileManager defaultManager];
            if ([fm fileExistsAtPath:PM_tccPath()]) {
                [log appendFormat:@"TCC.db 存在: YES\n"];
                sqlite3 *db = PM_openTCC();
                if (db) {
                    sqlite3_stmt *s = NULL;
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
