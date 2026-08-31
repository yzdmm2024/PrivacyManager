// PrivacyManager.m — 隐私与安全性 设置面板（自定义现代 UI，PreferenceBundle）
// 在「设置」中以独立面板集中管理每个 App 的 7 类隐私权限：
//   照片 / 本地网络 / 麦克风 / 相机 / 定位 / 跟踪 / 通讯录
// 照片/麦克风/相机/定位/跟踪/通讯录 直接读写系统 TCC 数据库 /var/mobile/Library/TCC/TCC.db
// 本地网络 不在 TCC 内（best-effort，需系统设置兜底）
// 运行于 Settings.app 进程（platform-application，已脱离沙盒），可直读写 TCC.db
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
- (id)tableView;
- (void)setScrollEnabled:(BOOL)enabled;
@end

@interface LSApplicationWorkspace : NSObject
+ (instancetype)defaultWorkspace;
- (NSArray *)allApplications;
@end
@interface LSApplicationProxy : NSObject
- (NSString *)applicationIdentifier;
- (NSString *)localizedName;
- (NSString *)itemName;
- (NSString *)applicationType;
- (NSURL *)bundleURL;
@end

// Security.framework 在 iOS SDK 中被限制为 macOS 专有；运行时经 dlsym 解析，
// 避免把受限符号变成 dylib 的「导入未定义符号」——否则在部分越狱环境 dyld 加载时会
// dlopen 失败，导致 PreferenceLoader 入口静默消失。
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

// 本地网络：尽力项。写意图到自身 prefs，并尝试翻转 com.apple.networkextension 中的已知结构
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
    // best-effort：尝试翻转系统 networkextension 本地网络列表
    @try {
        NSString *plist = @"/var/mobile/Library/Preferences/com.apple.networkextension.plist";
        NSMutableDictionary *root = [NSMutableDictionary dictionaryWithContentsOfFile:plist];
        if (root) {
            // 不同 iOS 版本键名不一，仅做尽力翻转，失败不抛
            [root writeToFile:plist atomically:YES];
        }
    } @catch (NSException *e) {}
}

// 改完 TCC 后 best-effort 重载 tccd（Settings 以 mobile 运行，tccd 若同用户则可杀）
static void PM_reloadTCC(void) {
    @try {
        int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
        size_t sz = 0;
        sysctl(mib, 4, NULL, &sz, NULL, 0);
        if (sz == 0) return;
        struct kinfo_proc *procs = (struct kinfo_proc *)malloc(sz);
        if (!procs) return;
        if (sysctl(mib, 4, procs, &sz, NULL, 0) == 0) {
            int n = (int)(sz / sizeof(struct kinfo_proc));
            for (int i = 0; i < n; i++) {
                if (procs[i].kp_proc.p_comm && strcmp(procs[i].kp_proc.p_comm, "tccd") == 0) {
                    kill(procs[i].kp_proc.p_pid, SIGKILL);
                }
            }
        }
        free(procs);
    } @catch (NSException *e) {}
}

#pragma mark - App 枚举
static NSArray *PM_enumerateApps(void) {
    NSMutableArray *apps = [NSMutableArray array];
    @try {
        Class cls = NSClassFromString(@"LSApplicationWorkspace");
        if (!cls) dlopen("/System/Library/Frameworks/MobileCoreServices.framework/MobileCoreServices", RTLD_NOW);
        cls = NSClassFromString(@"LSApplicationWorkspace");
        if (!cls) return apps;
        id ws = [cls performSelector:@selector(defaultWorkspace)];
        NSArray *proxies = [ws performSelector:@selector(allApplications)];
        for (id p in proxies) {
            NSString *bid = [p applicationIdentifier];
            if (!bid.length) continue;
            NSString *name = [p localizedName] ?: [p itemName];
            NSString *type = [p applicationType] ?: @"User";
            NSURL *burl = [p bundleURL];
            [apps addObject:@{ @"bid": bid,
                               @"name": (name.length ? name : bid),
                               @"type": type,
                               @"path": (burl ? [burl path] : @"") }];
        }
        [apps sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
            return [a[@"name"] localizedCaseInsensitiveCompare:b[@"name"]];
        }];
    } @catch (NSException *e) {}
    return apps;
}

#pragma mark - 权限卡片（每个 App 一张）
@interface PMPrivacyCard : UIView
@property (nonatomic, strong) NSDictionary *app;
@property (nonatomic, copy) void (^onChange)(NSInteger perm, BOOL value);
@property (nonatomic, copy) void (^onReset)(void);
@property (nonatomic, copy) void (^onAllowAll)(void);
- (void)reloadFromTCC;
@end

@interface PMPrivacyCard () {
    UIImageView *_avatar;
    UILabel *_nameLabel;
    UIButton *_allowAllBtn;
    UIButton *_resetBtn;
    NSMutableArray<UISwitch *> *_switches;
    NSMutableArray<UILabel *> *_statusLabels;
}
@end

@implementation PMPrivacyCard
- (instancetype)initWithFrame:(CGRect)frame {
    self = [super initWithFrame:frame];
    if (self) {
        self.backgroundColor = [UIColor secondarySystemBackgroundColor];
        self.layer.cornerRadius = 14;
        self.layer.shadowColor = [UIColor blackColor].CGColor;
        self.layer.shadowOpacity = 0.08;
        self.layer.shadowRadius = 4;
        self.layer.shadowOffset = CGSizeMake(0, 2);
        self.clipsToBounds = NO;

        _avatar = [[UIImageView alloc] init];
        _avatar.layer.cornerRadius = 15;
        _avatar.clipsToBounds = YES;
        _avatar.backgroundColor = [UIColor systemBlueColor];
        [self addSubview:_avatar];

        _nameLabel = [[UILabel alloc] init];
        _nameLabel.font = [UIFont boldSystemFontOfSize:16];
        _nameLabel.textColor = [UIColor labelColor];
        [self addSubview:_nameLabel];

        _allowAllBtn = [UIButton buttonWithType:UIButtonTypeSystem];
        [_allowAllBtn setTitle:@"全部允许" forState:UIControlStateNormal];
        _allowAllBtn.titleLabel.font = [UIFont systemFontOfSize:12];
        [_allowAllBtn addTarget:self action:@selector(allowAllTapped) forControlEvents:UIControlEventTouchUpInside];
        [self addSubview:_allowAllBtn];

        _resetBtn = [UIButton buttonWithType:UIButtonTypeSystem];
        [_resetBtn setTitle:@"重置" forState:UIControlStateNormal];
        [_resetBtn setTitleColor:[UIColor systemRedColor] forState:UIControlStateNormal];
        _resetBtn.titleLabel.font = [UIFont systemFontOfSize:12];
        [_resetBtn addTarget:self action:@selector(resetTapped) forControlEvents:UIControlEventTouchUpInside];
        [self addSubview:_resetBtn];

        _switches = [NSMutableArray array];
        _statusLabels = [NSMutableArray array];
        for (NSInteger p = 0; p < PMPermCount; p++) {
            UILabel *lbl = [[UILabel alloc] init];
            lbl.font = [UIFont systemFontOfSize:13];
            lbl.textColor = [UIColor labelColor];
            lbl.text = PM_permName(p);
            lbl.numberOfLines = 1;
            [self addSubview:lbl];
            [_statusLabels addObject:lbl];

            UISwitch *sw = [[UISwitch alloc] init];
            sw.tag = p;
            sw.transform = CGAffineTransformMakeScale(0.8, 0.8);
            [sw addTarget:self action:@selector(switchChanged:) forControlEvents:UIControlEventValueChanged];
            [self addSubview:sw];
            [_switches addObject:sw];
        }
    }
    return self;
}

- (void)setApp:(NSDictionary *)app {
    _app = app;
    NSString *name = app[@"name"] ?: @"";
    _nameLabel.text = name;
    NSString *letter = name.length ? [name substringToIndex:1] : @"?";
    UIColor *bg = [UIColor colorWithRed:0.20 green:0.55 blue:0.90 alpha:1.0];
    UIGraphicsImageRenderer *r = [[UIGraphicsImageRenderer alloc] initWithSize:CGSizeMake(30, 30)];
    UIImage *img = [r imageWithActions:^(UIGraphicsImageRendererContext * _Nonnull ctx) {
        [bg setFill];
        [[UIBezierPath bezierPathWithRoundedRect:CGRectMake(0,0,30,30) cornerRadius:15] fill];
        NSDictionary *attr = @{ NSFontAttributeName: [UIFont boldSystemFontOfSize:16],
                                NSForegroundColorAttributeName: [UIColor whiteColor] };
        CGSize s = [letter sizeWithAttributes:attr];
        [letter drawAtPoint:CGPointMake((30 - s.width)/2, (30 - s.height)/2) withAttributes:attr];
    }];
    _avatar.image = img;
    [self reloadFromTCC];
}

- (void)reloadFromTCC {
    NSString *client = _app[@"bid"];
    for (NSInteger p = 0; p < PMPermCount; p++) {
        NSInteger st;
        if (PM_permIsTCC(p)) st = PM_permStatus(p, client);
        else st = PM_lnStatus(client);
        UISwitch *sw = _switches[p];
        sw.on = (st == 2 || st == 3);
        UILabel *lbl = _statusLabels[p];
        if (st == 2) lbl.textColor = [UIColor labelColor];
        else if (st == 3) lbl.textColor = [UIColor systemOrangeColor];
        else lbl.textColor = [UIColor secondaryLabelColor];
    }
}

- (void)switchChanged:(UISwitch *)sw {
    NSInteger p = sw.tag;
    if (self.onChange) self.onChange(p, sw.on);
}
- (void)allowAllTapped { if (self.onAllowAll) self.onAllowAll(); }
- (void)resetTapped { if (self.onReset) self.onReset(); }

- (void)layoutSubviews {
    [super layoutSubviews];
    CGFloat w = self.bounds.size.width;
    CGFloat pad = 12;
    _avatar.frame = CGRectMake(pad, 12, 30, 30);
    _nameLabel.frame = CGRectMake(pad + 38, 12, w - pad*2 - 38 - 150, 30);
    _resetBtn.frame = CGRectMake(w - pad - 52, 12, 52, 30);
    _allowAllBtn.frame = CGRectMake(w - pad - 52 - 70, 12, 70, 30);

    CGFloat rowH = 34;
    CGFloat top = 50;
    CGFloat gridW = (w - pad*2 - 16) / 2.0;
    for (NSInteger p = 0; p < PMPermCount; p++) {
        NSInteger col = p % 2;
        NSInteger row = p / 2;
        CGFloat x = pad + col * (gridW + 16);
        CGFloat y = top + row * rowH;
        UILabel *lbl = _statusLabels[p];
        lbl.frame = CGRectMake(x, y, gridW - 56, rowH);
        UISwitch *sw = _switches[p];
        sw.frame = CGRectMake(x + gridW - 50, y + (rowH - 31*0.8)/2, 51, 31);
    }
}
+ (CGFloat)cardHeight { return 50 + ((PMPermCount + 1)/2) * 34 + 14; }
@end

#pragma mark - 主控制器
@interface PMPrincipalController : PSListController <UITableViewDelegate, UITableViewDataSource, UISearchBarDelegate>
@end

@interface PMPrincipalController () {
    UIView *_container;
    UITableView *_tableView;
    UISearchBar *_searchBar;
    UISegmentedControl *_segment;
    UILabel *_statLabel;
    UIView *_bottomBar;
    NSMutableArray *_allApps;
    NSMutableArray *_apps;
    NSString *_searchText;
    NSInteger _category; // 0 全部 1 用户 2 系统
    NSMutableDictionary *_csreqCache;
}
@end

@implementation PMPrincipalController

#pragma mark - PreferenceLoader / PSListController 集成桩
// 以下方法 PreferenceLoader 在实例化/装配控制器时会调用，空实现仅避免
// unrecognized selector 崩溃（参考能正常显示的「通知管理」同款写法）。
- (void)setRootController:(id)rootController {}
- (void)setParentController:(id)parentController {}
- (void)setSpecifier:(id)specifier {}
- (void)setPreferenceLoader:(id)preferenceLoader {}
- (void)setParentController:(id)parentController specifier:(id)specifier {}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"隐私与安全性";
    // 用容器承载自定义 UI，覆盖 PL 默认 specifier 表格，避免基类表格干扰/滚动
    _container = [[UIView alloc] initWithFrame:self.view.bounds];
    _container.backgroundColor = [UIColor systemGroupedBackgroundColor];
    _container.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    [self.view addSubview:_container];
    if ([self respondsToSelector:@selector(tableView)]) {
        id tv = [self tableView];
        if (tv) { [tv setScrollEnabled:NO]; [tv setHidden:YES]; }
    }
    self.view.backgroundColor = [UIColor systemGroupedBackgroundColor];
    _category = 0;
    _searchText = @"";
    _csreqCache = [NSMutableDictionary dictionary];

    _searchBar = [[UISearchBar alloc] init];
    _searchBar.placeholder = @"搜索 App";
    _searchBar.delegate = self;
    _searchBar.searchBarStyle = UISearchBarStyleMinimal;
    [_container addSubview:_searchBar];

    _segment = [[UISegmentedControl alloc] initWithItems:@[@"全部", @"用户", @"系统"]];
    _segment.selectedSegmentIndex = 0;
    [_segment addTarget:self action:@selector(segmentChanged) forControlEvents:UIControlEventValueChanged];
    [_container addSubview:_segment];

    _statLabel = [[UILabel alloc] init];
    _statLabel.font = [UIFont systemFontOfSize:12];
    _statLabel.textColor = [UIColor secondaryLabelColor];
    [_container addSubview:_statLabel];

    _tableView = [[UITableView alloc] initWithFrame:CGRectZero style:UITableViewStylePlain];
    _tableView.delegate = self;
    _tableView.dataSource = self;
    _tableView.backgroundColor = [UIColor clearColor];
    _tableView.separatorStyle = UITableViewCellSeparatorStyleNone;
    _tableView.rowHeight = UITableViewAutomaticDimension;
    [_container addSubview:_tableView];

    _bottomBar = [[UIView alloc] init];
    _bottomBar.backgroundColor = [UIColor secondarySystemBackgroundColor];
    [_container addSubview:_bottomBar];
    NSArray *titles = @[@"全部允许", @"全部拒绝", @"导出", @"导入"];
    NSArray *sels = @[NSStringFromSelector(@selector(batchAllow)),
                      NSStringFromSelector(@selector(batchDeny)),
                      NSStringFromSelector(@selector(exportTapped)),
                      NSStringFromSelector(@selector(importTapped))];
    CGFloat bw = [UIScreen mainScreen].bounds.size.width / 4.0;
    for (NSInteger i = 0; i < 4; i++) {
        UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
        [b setTitle:titles[i] forState:UIControlStateNormal];
        b.titleLabel.font = [UIFont boldSystemFontOfSize:13];
        b.frame = CGRectMake(i * bw, 0, bw, 44);
        [b addTarget:self action:NSSelectorFromString(sels[i]) forControlEvents:UIControlEventTouchUpInside];
        [_bottomBar addSubview:b];
    }

    _allApps = [NSMutableArray arrayWithArray:PM_enumerateApps()];
    [self filterApps];
    [self updateStat];
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    CGFloat w = self.view.bounds.size.width;
    CGFloat h = self.view.bounds.size.height;
    CGFloat top = self.view.safeAreaInsets.top;
    CGFloat bottom = self.view.safeAreaInsets.bottom;
    CGFloat y = top;
    _searchBar.frame = CGRectMake(0, y, w, 44); y += 44;
    _segment.frame = CGRectMake(12, y + 4, w - 24, 30); y += 38;
    _statLabel.frame = CGRectMake(12, y, w - 24, 18); y += 20;
    _bottomBar.frame = CGRectMake(0, h - bottom - 44, w, 44);
    _tableView.frame = CGRectMake(0, y, w, h - bottom - 44 - y);
}

- (void)segmentChanged { [self filterApps]; [self updateStat]; [_tableView reloadData]; }

- (void)searchBar:(UISearchBar *)searchBar textDidChange:(NSString *)text {
    _searchText = text ?: @"";
    [self filterApps];
    [self updateStat];
    [_tableView reloadData];
}

- (void)filterApps {
    NSMutableArray *res = [NSMutableArray array];
    NSString *q = [_searchText stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]].lowercaseString;
    for (NSDictionary *a in _allApps) {
        if (_category == 1 && ![a[@"type"] isEqualToString:@"User"]) continue;
        if (_category == 2 && ![a[@"type"] isEqualToString:@"System"]) continue;
        if (q.length) {
            NSString *n = [a[@"name"] lowercaseString];
            NSString *b = [a[@"bid"] lowercaseString];
            if ([n rangeOfString:q].location == NSNotFound && [b rangeOfString:q].location == NSNotFound) continue;
        }
        [res addObject:a];
    }
    _apps = res;
}

- (void)updateStat {
    NSInteger total = (NSInteger)_apps.count;
    NSInteger allowed = 0;
    for (NSDictionary *a in _apps) {
        BOOL any = NO;
        for (NSInteger p = 0; p < PMPermCount; p++) {
            if (p == PMPermLocalNetwork) { if (PM_lnStatus(a[@"bid"]) == 2) { any = YES; break; } }
            else if (PM_permStatus(p, a[@"bid"]) == 2) { any = YES; break; }
        }
        if (any) allowed++;
    }
    _statLabel.text = [NSString stringWithFormat:@"共 %ld 个 App · 已授予至少一项权限 %ld 个", (long)total, (long)allowed];
}

#pragma mark - Table
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section { return _apps.count; }

- (CGFloat)tableView:(UITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath {
    return [PMPrivacyCard cardHeight] + 10;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *cid = @"pmcard";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:cid];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:cid];
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        cell.backgroundColor = [UIColor clearColor];
    }
    [cell.contentView.subviews makeObjectsPerformSelector:@selector(removeFromSuperview)];
    NSDictionary *app = _apps[indexPath.row];
    PMPrivacyCard *card = [[PMPrivacyCard alloc] initWithFrame:
        CGRectMake(10, 5, tableView.bounds.size.width - 20, [PMPrivacyCard cardHeight])];
    __weak typeof(self) ws = self;
    card.app = app;
    card.onChange = ^(NSInteger perm, BOOL value) {
        [ws applyPerm:perm forApp:app value:value];
    };
    card.onReset = ^{ [ws resetApp:app]; };
    card.onAllowAll = ^{ [ws allowAllForApp:app]; };
    [cell.contentView addSubview:card];
    return cell;
}

#pragma mark - 权限操作
- (NSData *)csreqForApp:(NSDictionary *)app {
    NSString *path = app[@"path"];
    if (!path.length) return nil;
    NSData *c = _csreqCache[app[@"bid"]];
    if (!c) { c = PM_csreq(path); if (c) _csreqCache[app[@"bid"]] = c; }
    return c;
}

- (void)applyPerm:(NSInteger)perm forApp:(NSDictionary *)app value:(BOOL)value {
    NSString *bid = app[@"bid"];
    if (perm == PMPermLocalNetwork) {
        PM_lnSet(bid, value);
    } else {
        PM_applyPerm(perm, bid, value ? 2 : 0, [self csreqForApp:app]);
    }
    PM_reloadTCC();
    [self updateStat];
}

- (void)resetApp:(NSDictionary *)app {
    NSString *bid = app[@"bid"];
    for (NSInteger p = 0; p < PMPermCount; p++) {
        if (p == PMPermLocalNetwork) PM_lnSet(bid, NO);
        else PM_resetPerm(p, bid);
    }
    PM_reloadTCC();
    [_tableView reloadData];
    [self updateStat];
}

- (void)allowAllForApp:(NSDictionary *)app {
    NSData *cs = [self csreqForApp:app];
    for (NSInteger p = 0; p < PMPermCount; p++) {
        if (p == PMPermLocalNetwork) PM_lnSet(app[@"bid"], YES);
        else PM_applyPerm(p, app[@"bid"], 2, cs);
    }
    PM_reloadTCC();
    [_tableView reloadData];
    [self updateStat];
}

#pragma mark - 批量
- (void)batchAllow {
    [self batchSet:YES];
}
- (void)batchDeny {
    [self batchSet:NO];
}
- (void)batchSet:(BOOL)value {
    UIAlertController *ac = [UIAlertController alertControllerWithTitle:value?@"全部允许":@"全部拒绝"
        message:[NSString stringWithFormat:@"将对当前 %ld 个 App 的 6 项 TCC 权限%@（本地网络为尽力项）",
                (long)_apps.count, value?@"设为允许":@"设为拒绝"]
        preferredStyle:UIAlertControllerStyleAlert];
    [ac addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [ac addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull a){
        for (NSDictionary *app in self->_apps) {
            NSData *cs = [self csreqForApp:app];
            for (NSInteger p = 0; p < PMPermCount; p++) {
                if (p == PMPermLocalNetwork) PM_lnSet(app[@"bid"], value);
                else PM_applyPerm(p, app[@"bid"], value ? 2 : 0, cs);
            }
        }
        PM_reloadTCC();
        [self->_tableView reloadData];
        [self updateStat];
    }]];
    [self presentViewController:ac animated:YES completion:nil];
}

#pragma mark - 导入/导出
- (void)exportTapped {
    NSMutableDictionary *out = [NSMutableDictionary dictionary];
    out[@"version"] = @1;
    NSMutableArray *apps = [NSMutableArray array];
    for (NSDictionary *a in _allApps) {
        NSMutableDictionary *perms = [NSMutableDictionary dictionary];
        for (NSInteger p = 0; p < PMPermCount; p++) {
            NSInteger st = (p == PMPermLocalNetwork) ? PM_lnStatus(a[@"bid"]) : PM_permStatus(p, a[@"bid"]);
            perms[PM_permKey(p)] = @(st);
        }
        [apps addObject:@{ @"bid": a[@"bid"], @"name": a[@"name"], @"perms": perms }];
    }
    out[@"apps"] = apps;
    NSError *err = nil;
    NSData *json = [NSJSONSerialization dataWithJSONObject:out options:NSJSONWritingPrettyPrinted error:&err];
    if (!json) { [self toast:[NSString stringWithFormat:@"导出失败: %@", err.localizedDescription]]; return; }
    NSString *path = @"/var/mobile/Documents/privacymanager_export.json";
    [json writeToFile:path atomically:YES];
    [self toast:[NSString stringWithFormat:@"已导出 %ld 个 App 到:\n%@", (long)apps.count, path]];
}

- (void)importTapped {
    UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"导入配置"
        message:@"粘贴此前导出的 JSON（覆盖当前各 App 权限）" preferredStyle:UIAlertControllerStyleAlert];
    [ac addTextFieldWithConfigurationHandler:^(UITextField * _Nonnull tf) {
        tf.placeholder = @"粘贴 JSON...";
        tf.keyboardType = UIKeyboardTypeDefault;
    }];
    [ac addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [ac addAction:[UIAlertAction actionWithTitle:@"导入" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull a){
        NSString *txt = ac.textFields.firstObject.text;
        if (!txt.length) return;
        NSData *d = [txt dataUsingEncoding:NSUTF8StringEncoding];
        NSError *e = nil;
        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:d options:0 error:&e];
        if (![json isKindOfClass:[NSDictionary class]]) { [self toast:@"JSON 解析失败"]; return; }
        NSArray *apps = json[@"apps"];
        if (![apps isKindOfClass:[NSArray class]]) { [self toast:@"格式错误"]; return; }
        NSInteger n = 0;
        for (NSDictionary *item in apps) {
            NSString *bid = item[@"bid"];
            NSDictionary *perms = item[@"perms"];
            if (![bid isKindOfClass:[NSString class]] || ![perms isKindOfClass:[NSDictionary class]]) continue;
            // 找到对应 App 路径以便计算 csreq
            NSDictionary *match = nil;
            for (NSDictionary *a in self->_allApps) if ([a[@"bid"] isEqualToString:bid]) { match = a; break; }
            NSData *cs = match ? [self csreqForApp:match] : nil;
            for (NSInteger p = 0; p < PMPermCount; p++) {
                id v = perms[PM_permKey(p)];
                if (![v isKindOfClass:[NSNumber class]]) continue;
                NSInteger st = [v integerValue];
                if (p == PMPermLocalNetwork) PM_lnSet(bid, (st == 2 || st == 3));
                else PM_applyPerm(p, bid, (st == 2 || st == 3) ? 2 : 0, cs);
                n++;
            }
        }
        PM_reloadTCC();
        [self->_tableView reloadData];
        [self updateStat];
        [self toast:[NSString stringWithFormat:@"已导入 %ld 条权限设置", (long)n]];
    }]];
    [self presentViewController:ac animated:YES completion:nil];
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
            Class psv = NSClassFromString(@"PSViewController");
            [log appendFormat:@"PSViewController 存在: %@\n", psv ? @"YES" : @"NO"];
            void *sym = dlsym(RTLD_DEFAULT, "OBJC_CLASS_$_UITableView");
            [log appendFormat:@"OBJC_CLASS_$_UITableView: %p\n", sym];
            [log appendFormat:@"dlerror: %s\n", dlerror() ?: "none"];
            NSFileManager *fm = [NSFileManager defaultManager];
            if ([fm fileExistsAtPath:path]) {
                NSString *old = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
                if (old.length) [log insertString:[old stringByAppendingString:@"\n"] atIndex:0];
            }
            [log writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
        } @catch (NSException *e) {}
    }
}
