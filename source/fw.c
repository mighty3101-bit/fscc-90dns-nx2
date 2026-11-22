#include <string.h>
#include <switch.h>
#include <kaihen.h>
#include "main.h"
static Result querySetSysViaKaihen(SetSysFirmwareVersion *out) {
    Service ro = {0}, hen = {0}, setsys = {0};
    Handle h = INVALID_HANDLE;
    Result rc = kaihenGetRoSession(&ro);
    if (R_FAILED(rc)) return rc;
    rc = kaihenOpenHomebrewSession(&ro, &hen);
    if (R_FAILED(rc)) return rc;
    rc = henGetSettingsSession(&hen, &h);
    serviceClose(&hen);
    if (R_FAILED(rc) || h == INVALID_HANDLE) return R_FAILED(rc) ? rc : MAKERESULT(Module_Libnx, LibnxError_NotFound);
    serviceCreate(&setsys, h);
    rc = serviceDispatch(&setsys, 4,
        .buffer_attrs = { SfBufferAttr_FixedSize | SfBufferAttr_HipcPointer | SfBufferAttr_Out },
        .buffers = { { out, sizeof(*out) } }
    );
    if (R_FAILED(rc)) {
        rc = serviceDispatch(&setsys, 3,
            .buffer_attrs = { SfBufferAttr_FixedSize | SfBufferAttr_HipcPointer | SfBufferAttr_Out },
            .buffers = { { out, sizeof(*out) } }
        );
    }
    serviceClose(&setsys);
    return rc;
}
void detectRealFirmware(FwInfo *out) {
    memset(out, 0, sizeof(*out));
    u32 h = hosversionGet();
    out->is_kaihen = hosversionIsKaiHEN();
    out->major = HOSVER_MAJOR(h);
    out->minor = HOSVER_MINOR(h);
    out->micro = HOSVER_MICRO(h);
    SetSysFirmwareVersion fw;
    memset(&fw, 0, sizeof(fw));
    Result rc = setsysInitialize();
    if (R_SUCCEEDED(rc)) {
        rc = setsysGetFirmwareVersion(&fw);
        setsysExit();
        if (R_SUCCEEDED(rc)) {
            out->major = fw.major; out->minor = fw.minor; out->micro = fw.micro;
            out->rev_major = fw.revision_major; out->rev_minor = fw.revision_minor;
            out->real_from_setsys = true;
            hosversionSet(MAKEHOSVERSION(fw.major, fw.minor, fw.micro) | (out->is_kaihen ? BIT(30) : 0));
            return;
        }
    }
    out->setsys_rc = rc;
    memset(&fw, 0, sizeof(fw));
    rc = querySetSysViaKaihen(&fw);
    if (R_SUCCEEDED(rc)) {
        out->major = fw.major; out->minor = fw.minor; out->micro = fw.micro;
        out->rev_major = fw.revision_major; out->rev_minor = fw.revision_minor;
        out->via_kaihen_fallback = true;
        hosversionSet(MAKEHOSVERSION(fw.major, fw.minor, fw.micro) | (out->is_kaihen ? BIT(30) : 0));
    } else { out->setsys_rc = rc; }
}
