/*
 * TrustForgePlugin_stub.m - SDK-free stub for hosts whose Security.framework
 * does not expose <Security/AuthorizationPlugin.h>.
 *
 * Status: Draft (Phase 0). No-op shim; fails closed (deny) for any right
 * routed to it. Useful only to verify that:
 *   1. The bundle layout under /Library/Security/SecurityAgentPlugins/ loads.
 *   2. authorizationdb has been wired correctly to refer to
 *      "com.trustforge.AuthPlugin:gate".
 *
 * This file deliberately does NOT include <Security/Authorization.h> or
 * <Security/AuthorizationPlugin.h>: on hosts that have those headers we
 * would rather build the real TrustForgePlugin.m. The stub is for hosts that
 * cannot compile the full plugin at all. To keep the build hermetic we
 * forward-declare every symbol we use.
 *
 * To use:
 *   make stub
 *
 * Replace with the real TrustForgePlugin.m once you have an SDK that exposes
 * the plugin interface header. The Info.plist and bundle layout are
 * identical between stub and full builds.
 */

#include <stdint.h>
#include <syslog.h>

/* OSStatus is plain int32_t on all macOS targets. */
typedef int32_t OSStatus;

/* Auth result codes - values from Security/SecBase.h (stable since 10.0). */
enum {
    errAuthorizationSuccess  =      0,
    errAuthorizationInternal = -60008,
    errAuthorizationDenied   = -60005,
};

typedef void *AuthorizationPluginRef;
typedef void *AuthorizationMechanismRef;
typedef void *AuthorizationEngineRef;
typedef const char *AuthorizationMechanismIdStub;

typedef struct {
    uint32_t version;
    OSStatus (*PluginDestroy)(AuthorizationPluginRef);
    OSStatus (*MechanismCreate)(AuthorizationPluginRef, AuthorizationEngineRef,
                                AuthorizationMechanismIdStub,
                                AuthorizationMechanismRef *);
    OSStatus (*MechanismInvoke)(AuthorizationMechanismRef);
    OSStatus (*MechanismDeactivate)(AuthorizationMechanismRef);
    OSStatus (*MechanismDestroy)(AuthorizationMechanismRef);
} AuthorizationPluginInterfaceStub;

static OSStatus
TFStub_PluginDestroy(AuthorizationPluginRef p) {
    (void)p;
    return errAuthorizationSuccess;
}

static OSStatus
TFStub_MechanismCreate(AuthorizationPluginRef p,
                       AuthorizationEngineRef e,
                       AuthorizationMechanismIdStub mid,
                       AuthorizationMechanismRef *out) {
    (void)p; (void)e; (void)mid;
    if (out) *out = (AuthorizationMechanismRef)(uintptr_t)1;
    return errAuthorizationSuccess;
}

static OSStatus
TFStub_MechanismInvoke(AuthorizationMechanismRef m) {
    (void)m;
    /* Stub fails closed: cannot call SetResult without callbacks vtable, so
     * the engine treats us as undefined and the right's rule decides. The
     * stub is deliberately not "allow". */
    syslog(LOG_NOTICE, "trustforge-stub: invoke (no-op deny)");
    return errAuthorizationDenied;
}

static OSStatus
TFStub_MechanismDeactivate(AuthorizationMechanismRef m) {
    (void)m;
    return errAuthorizationSuccess;
}

static OSStatus
TFStub_MechanismDestroy(AuthorizationMechanismRef m) {
    (void)m;
    return errAuthorizationSuccess;
}

static const AuthorizationPluginInterfaceStub gStubInterface = {
    .version             = 0,
    .PluginDestroy       = TFStub_PluginDestroy,
    .MechanismCreate     = TFStub_MechanismCreate,
    .MechanismInvoke     = TFStub_MechanismInvoke,
    .MechanismDeactivate = TFStub_MechanismDeactivate,
    .MechanismDestroy    = TFStub_MechanismDestroy,
};

OSStatus
AuthorizationPluginCreate(const void *callbacks,
                          AuthorizationPluginRef *outPlugin,
                          const void **outPluginInterface);

OSStatus
AuthorizationPluginCreate(const void *callbacks,
                          AuthorizationPluginRef *outPlugin,
                          const void **outPluginInterface)
{
    (void)callbacks;
    if (!outPlugin || !outPluginInterface) return errAuthorizationInternal;
    *outPlugin = (AuthorizationPluginRef)(uintptr_t)1;
    *outPluginInterface = &gStubInterface;
    openlog("TrustForgeAuthPluginStub", LOG_PID | LOG_NDELAY, LOG_AUTH);
    syslog(LOG_NOTICE,
           "trustforge-stub: loaded; AuthorizationPlugin.h was unavailable at "
           "build time. All decisions deny. Rebuild with `make` once the "
           "full SDK header is present.");
    return errAuthorizationSuccess;
}
