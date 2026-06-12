/*
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

/* Read VirtualizationBasedSecurityStatus and CodeIntegrityPolicyEnforcementStatus
 * from the single Win32_DeviceGuard instance in one WMI session. Returns FALSE if
 * WMI is unavailable or neither property is present. COM init/uninit is balanced per
 * call unless COM was already initialised (RPC_E_CHANGED_MODE), in which case we
 * use the existing apartment without uninitialising on exit.
 * HK-UNCERTAIN: Win32_DeviceGuard property availability varies by SKU/build —
 * confirm on the box; absence reads as 0. */
static BOOL HkReadDeviceGuardProps(uint32_t* vbs_status, uint32_t* ci_policy)
{
    HRESULT hr;
    IWbemLocator* loc = nullptr;
    IWbemServices* svc = nullptr;
    IEnumWbemClassObject* en = nullptr;
    IWbemClassObject* obj = nullptr;
    ULONG returned = 0;
    BOOL ok = FALSE;
    BOOL com_needs_uninit = FALSE;
    BSTR ns = nullptr;
    BSTR query = nullptr;
    BSTR lang = nullptr;

    hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr)) {
        com_needs_uninit = TRUE;
    } else if (hr == RPC_E_CHANGED_MODE) {
        /* COM already initialised with a different apartment model — usable as-is;
         * do not balance with CoUninitialize since we did not increment the refcount. */
    } else {
        return FALSE; /* genuine COM init failure */
    }

    ns    = SysAllocString(L"ROOT\\Microsoft\\Windows\\DeviceGuard");
    query = SysAllocString(L"SELECT * FROM Win32_DeviceGuard");
    lang  = SysAllocString(L"WQL");
    if (!ns || !query || !lang) goto release;

    hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator, (void**)&loc);
    if (FAILED(hr) || loc == nullptr) goto release;
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
        if (vbs_status != nullptr &&
            SUCCEEDED(obj->Get(L"VirtualizationBasedSecurityStatus", 0, &v, nullptr, nullptr))) {
            if (v.vt == VT_I4 || v.vt == VT_UI4) {
                *vbs_status = (uint32_t)v.ulVal;
                ok = TRUE;
            }
        }
        VariantClear(&v);
        VariantInit(&v);
        if (ci_policy != nullptr &&
            SUCCEEDED(obj->Get(L"CodeIntegrityPolicyEnforcementStatus", 0, &v, nullptr, nullptr))) {
            if (v.vt == VT_I4 || v.vt == VT_UI4) {
                *ci_policy = (uint32_t)v.ulVal;
                ok = TRUE;
            }
        }
        VariantClear(&v);
        obj->Release();
    }

release:
    if (en) en->Release();
    if (svc) svc->Release();
    if (loc) loc->Release();
    if (ns)    SysFreeString(ns);
    if (query) SysFreeString(query);
    if (lang)  SysFreeString(lang);
    if (com_needs_uninit) CoUninitialize();
    return ok;
}

extern "C" int hv_sample_vbs_attest(hv_vbs_attest* out)
{
    if (out == nullptr) {
        return HK_AC_NOT_IMPLEMENTED;
    }
    RtlSecureZeroMemory(out, sizeof(*out));

    HkReadDeviceGuardProps(&out->vbs_status, &out->ci_policy);
    /* SecurityServicesRunning array read deferred (HK-UNCERTAIN). */
    out->security_services = 0;

    /* HK-UNCERTAIN: Attestation::quote(nonce, nonce_len, out) is a NotImplemented
     * stub until a TPM2 backend lands (guardrail #10). The nonce is a server-issued
     * challenge bound into the quote (TPM qualifyingData). With no real backend,
     * attest_quote_avail stays 0 and the pure core hv_vbs_contradiction withholds
     * the contradiction (report-only, never enforced) — the plan's signal-40 posture. */
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
