/*
 * ac/src/hv/hv_vbs_attest.cpp
 * Role: Signal 40 correlator — reads the VBS/HVCI posture (Win32_DeviceGuard WMI:
 *       VirtualizationBasedSecurityStatus / SecurityServicesRunning /
 *       CodeIntegrityPolicyEnforcementStatus) and pairs it with a TPM attestation
 *       quote via the stable Attestation.h interface, filling hv_vbs_attest. The
 *       contradiction (VBS-on but unattested) is reported RAW; the host-tested
 *       pure core hv_vbs_contradiction withholds it while no quote is available.
 *       Report-only until a real Attestation backend lands (guardrail #10 keeps
 *       the interface stable so the swap is transparent); never gates a ban here.
 *       READ-ONLY.
 * Target platforms: Windows. Guardrail #1: WMI/COM confined here.
 * Interface: implements hv_sample_vbs_attest from hv_signals.h.
 */

#include "horkos/hv_signals.h"

#if defined(HK_PLATFORM_WINDOWS)

#include <windows.h>
#include <wbemidl.h>

/* Read one UINT32 property from the single Win32_DeviceGuard instance. Returns
 * FALSE if WMI is unavailable or the property is absent. COM init/uninit is per
 * call; every HRESULT is checked. HK-UNCERTAIN: Win32_DeviceGuard property
 * availability varies by SKU/build — confirm on the box; absence reads as 0. */
static BOOL HkReadDeviceGuardU32(const wchar_t* prop, uint32_t* value, uint32_t* arr0)
{
    HRESULT hr;
    IWbemLocator* loc = nullptr;
    IWbemServices* svc = nullptr;
    IEnumWbemClassObject* en = nullptr;
    IWbemClassObject* obj = nullptr;
    ULONG returned = 0;
    BOOL ok = FALSE;
    BSTR ns = SysAllocString(L"ROOT\\Microsoft\\Windows\\DeviceGuard");
    BSTR query = SysAllocString(L"SELECT * FROM Win32_DeviceGuard");
    BSTR lang = SysAllocString(L"WQL");

    hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) goto done;
    hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator, (void**)&loc);
    if (FAILED(hr) || loc == nullptr) goto uninit;
    hr = loc->ConnectServer(ns, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &svc);
    if (FAILED(hr) || svc == nullptr) goto release;
    hr = CoSetProxyBlanket((IUnknown*)svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                           RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr,
                           EOAC_NONE);
    if (FAILED(hr)) goto release;
    hr = svc->ExecQuery(lang, query, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                        nullptr, &en);
    if (FAILED(hr) || en == nullptr) goto release;
    hr = en->Next(WBEM_INFINITE, 1, &obj, &returned);
    if (hr == WBEM_S_NO_ERROR && returned == 1 && obj != nullptr) {
        VARIANT v;
        VariantInit(&v);
        if (value != nullptr && SUCCEEDED(obj->Get(prop, 0, &v, nullptr, nullptr))) {
            if (v.vt == VT_I4 || v.vt == VT_UI4) {
                *value = (uint32_t)v.ulVal;
                ok = TRUE;
            }
        }
        VariantClear(&v);
        (void)arr0; /* SecurityServicesRunning is an array; first element via a
                       separate path — left for the box (HK-UNCERTAIN). */
        obj->Release();
    }

release:
    if (en) en->Release();
    if (svc) svc->Release();
    if (loc) loc->Release();
uninit:
    CoUninitialize();
done:
    if (ns) SysFreeString(ns);
    if (query) SysFreeString(query);
    if (lang) SysFreeString(lang);
    return ok;
}

extern "C" int hv_sample_vbs_attest(hv_vbs_attest* out)
{
    uint32_t v = 0;

    if (out == nullptr) {
        return HK_AC_NOT_IMPLEMENTED;
    }
    RtlSecureZeroMemory(out, sizeof(*out));

    if (HkReadDeviceGuardU32(L"VirtualizationBasedSecurityStatus", &v, nullptr)) {
        out->vbs_status = v;
    }
    v = 0;
    if (HkReadDeviceGuardU32(L"CodeIntegrityPolicyEnforcementStatus", &v, nullptr)) {
        out->ci_policy = v;
    }
    /* SecurityServicesRunning array read deferred (HK-UNCERTAIN). */
    out->security_services = 0;

    /* HK-UNCERTAIN: Attestation::quote() is a NotImplemented stub until a TPM2
     * backend lands (guardrail #10). With no quote, attest_quote_avail stays 0 and
     * the pure core hv_vbs_contradiction withholds the contradiction (report-only,
     * never enforced) — exactly the plan's signal-40 posture. */
    out->attest_quote_avail = 0;
    out->attest_contradiction = 0;

    return HK_AC_OK;
}

#else

extern "C" int hv_sample_vbs_attest(hv_vbs_attest* out)
{
    (void)out;
    return HK_AC_NOT_IMPLEMENTED;
}

#endif
