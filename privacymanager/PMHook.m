// PMHook.m — 隐私总开关（PrivacyManager）App 侧 hook
// 目的：抹除/还原手机设置后，App 调用 ATT（App Tracking Transparency）请求
// 「允许 XX 跟踪你在其他公司的 App 和网站上的活动」时，不再向系统发真实请求
// → 系统不弹授权框，直接按用户在「隐私总开关」面板里对该 App 的「跟踪」开关
//   静默回调 允许/拒绝（未配置的 App 默认拒绝，不跟踪）。
//
// 配置来源（与设置面板共享同一偏好域 com.ntm.privacymanager）：
//   PM_autoATT           缺省 YES —— 读取不到时视为开启（装上即生效）
//   PM_Track_<bundleID>  2=允许  0=拒绝（缺省 0=拒绝）
//
// 注入过滤：PMHook.plist（Filter: Classes = ATTrackingManager, Mode = Any）
// 仅注入存在 ATTrackingManager 类的进程（即真正使用 ATT 的 App）。

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

#pragma mark - ATT 状态（ATTrackingManagerAuthorizationStatus）
typedef NS_ENUM(NSInteger, PMHAttStatus) {
    PMHAttNotDetermined = 0,
    PMHAttRestricted    = 1,
    PMHAttDenied        = 2,
    PMHAttAuthorized    = 3,
};

#pragma mark - 配置读取
static NSUserDefaults *PMH_prefs(void) {
    static NSUserDefaults *p = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        p = [[NSUserDefaults alloc] initWithSuiteName:@"com.ntm.privacymanager"];
    });
    return p;
}

// 全局开关：默认开（装上即免弹窗；写 PM_autoATT=NO 可恢复系统原生弹窗）
static BOOL PMH_autoOn(void) {
    id v = [PMH_prefs() objectForKey:@"PM_autoATT"];
    return v ? [v boolValue] : YES;
}

// 本 App 的跟踪决定：面板镜像值 2=允许 0=拒绝；未配置默认拒绝
static NSInteger PMH_decision(void) {
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
    id v = [PMH_prefs() objectForKey:[@"PM_Track_" stringByAppendingString:bid]];
    return v ? [v integerValue] : 0;
}

static PMHAttStatus PMH_statusFor(NSInteger decision) {
    return (decision == 2) ? PMHAttAuthorized : PMHAttDenied;
}

#pragma mark - Hook
static void (*orig_requestAuth)(id, SEL, id);
static void hook_requestAuth(id self, SEL _cmd, id handler) {
    if (PMH_autoOn()) {
        PMHAttStatus st = PMH_statusFor(PMH_decision());
        if (handler) {
            @try {
                void (^block)(NSInteger) = (void (^)(NSInteger))handler;
                dispatch_async(dispatch_get_main_queue(), ^{ block(st); });
            } @catch (NSException *e) {}
        }
        return; // 不调用 original → 系统不弹「允许跟踪」授权框
    }
    if (orig_requestAuth) orig_requestAuth(self, _cmd, handler);
}

static NSInteger (*orig_status)(id, SEL);
static NSInteger hook_status(id self, SEL _cmd) {
    if (PMH_autoOn()) return (NSInteger)PMH_statusFor(PMH_decision());
    if (orig_status) return orig_status(self, _cmd);
    return (NSInteger)PMHAttNotDetermined;
}

#pragma mark - 安装
__attribute__((constructor))
static void PMH_init(void) {
    @try {
        Class cls = objc_getClass("ATTrackingManager");
        if (!cls) return;

        SEL reqSel = sel_registerName("requestTrackingAuthorizationWithCompletionHandler:");
        Method reqM = class_getInstanceMethod(cls, reqSel);
        if (reqM) {
            orig_requestAuth = (void (*)(id, SEL, id))method_getImplementation(reqM);
            method_setImplementation(reqM, (IMP)hook_requestAuth);
        }

        SEL stSel = sel_registerName("trackingAuthorizationStatus");
        Method stM = class_getInstanceMethod(cls, stSel);
        if (stM) {
            orig_status = (NSInteger (*)(id, SEL))method_getImplementation(stM);
            method_setImplementation(stM, (IMP)hook_status);
        }
    } @catch (NSException *e) {}
}
