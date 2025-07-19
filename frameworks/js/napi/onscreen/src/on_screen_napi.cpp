/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "on_screen_napi.h"

#include <mutex>

#include "devicestatus_define.h"
#include "fi_log.h"
#include "napi_constants.h"
#include "on_screen_manager.h"
#include "on_screen_napi_error.h"
#include "util_napi.h"

#undef LOG_TAG
#define LOG_TAG "OnScreenNapi"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
namespace {
constexpr uint8_t ARG_0 = 0;
constexpr uint8_t ARG_1 = 1;
OnScreenNapi *g_onScreenObj = nullptr;
std::mutex g_mtx;
} // namespace

OnScreenNapi::OnScreenNapi(napi_env env, napi_value thisVar)
{
    env_ = env;
}

OnScreenNapi::~OnScreenNapi() {}

napi_value OnScreenNapi::Init(napi_env env, napi_value exports)
{
    FI_HILOGD("Enter");
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_FUNCTION("sendControlEvent", SendControlEventNapi),
        DECLARE_NAPI_STATIC_FUNCTION("getPageContent", GetPageContentNapi),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc)/sizeof(desc[0]), desc));
    // 声明枚举值Scenario
    napi_value napiScenario;
    napi_status status = napi_create_object(env, &napiScenario);
    if (status != napi_ok) {
        FI_HILOGE("Failed create object");
        return exports;
    }
    bool ret = true;
    ret = SetInt32Property(env, napiScenario, static_cast<int32_t>(Scenario::UNKNOWN), "UNKNOWN");
    ret = ret && SetInt32Property(env, napiScenario, static_cast<int32_t>(Scenario::ARTICLE), "ARTICLE");
    ret = ret && SetPropertyName(env, exports, "Scenario", napiScenario);
    if (!ret) {
        FI_HILOGE("Failed set enum scenario");
        return exports;
    }
    // 声明枚举值EventType
    napi_value napiEventType;
    status = napi_create_object(env, &napiEventType);
    if (status != napi_ok) {
        FI_HILOGE("Failed create object");
        return exports;
    }
    ret = true;
    ret = ret &&
        SetInt32Property(env, napiEventType, static_cast<int32_t>(EventType::SCROLL_TO_HOOK), "SCROLL_TO_HOOK");
    ret = ret && SetPropertyName(env, exports, "EventType", napiEventType);
    if (!ret) {
        FI_HILOGE("Failed set enum eventtype");
        return exports;
    }
    FI_HILOGD("Exit");
    return exports;
}

napi_value OnScreenNapi::GetPageContentNapi(napi_env env, napi_callback_info info)
{
    FI_HILOGD("Enter");
    size_t argc = ARG_1;
    napi_value args[ARG_1] = { nullptr };
    napi_value jsThis = nullptr;
    ContentOption option;
    napi_status status = napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr);
    if (status != napi_ok) {
        ThrowOnScreenErr(env, SERVICE_EXCEPTION, "napi_get_cb_info failed");
        return nullptr;
    }
    if (!GetContentOption(env, args, argc, option)) {
        ThrowOnScreenErr(env, PARAM_EXCEPTION, "param is invalid");
        return nullptr;
    }
    {
        std::lock_guard lockGrd(g_mtx);
        if (!ConstructOnScreen(env, jsThis)) {
            ThrowOnScreenErr(env, SERVICE_EXCEPTION, "failed to get g_onScreenObj");
            return nullptr;
        }
    }
    napi_value promise = nullptr;
    napi_deferred deferred = nullptr;
    status = napi_create_promise(env, &deferred, &promise);
    if (status != napi_ok) {
        ThrowOnScreenErr(env, SERVICE_EXCEPTION, "Failed to create promise");
        return nullptr;
    }
    GetPageContentAsyncContext* asyncContext = new (std::nothrow) GetPageContentAsyncContext();
    CHKPP(asyncContext);
    asyncContext->env = env;
    asyncContext->deferred = deferred;
    asyncContext->option = option;
    FI_HILOGD("invoke get page content, windowid = %{public}d, contentUnderstand = %{public}d, pageLink = %{public}d,"
        "textOnly = %{public}d, maxParaLen = %{public}d", asyncContext->option.windowId, asyncContext->option.contentUnderstand,
        asyncContext->option.pageLink, asyncContext->option.textOnly, asyncContext->option.maxParagraphSize);
    if (!GetPageContentExec(asyncContext)) {
        FI_HILOGE("get page content execution failed");
        delete asyncContext;
        return nullptr;
    }
    return promise;
}

napi_value OnScreenNapi::SendControlEventNapi(napi_env env, napi_callback_info info)
{
    FI_HILOGD("Enter");
    size_t argc = ARG_1;
    napi_value args[ARG_1] = { nullptr };
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr);
    if (status != napi_ok) {
        ThrowOnScreenErr(env, SERVICE_EXCEPTION, "napi_get_cb_info failed");
        return nullptr;
    }
    ControlEvent event;
    if (!GetControlEvent(env, args, argc, event)) {
        ThrowOnScreenErr(env, PARAM_EXCEPTION, "param is invalid");
        return nullptr;
    }
    {
        std::lock_guard lockGrd(g_mtx);
        if (!ConstructOnScreen(env, jsThis)) {
            ThrowOnScreenErr(env, SERVICE_EXCEPTION, "failed to get g_onScreenObj");
            return nullptr;
        }
    }
    napi_value promise = nullptr;
    napi_deferred deferred = nullptr;
    status = napi_create_promise(env, &deferred, &promise);
    if (status != napi_ok) {
        ThrowOnScreenErr(env, SERVICE_EXCEPTION, "Failed to create promise");
        return nullptr;
    }
    SendControlEventAsyncContext* asyncContext = new (std::nothrow) SendControlEventAsyncContext();
    CHKPP(asyncContext);
    asyncContext->env = env;
    asyncContext->deferred = deferred;
    asyncContext->event = event;
    FI_HILOGD("invoke send control event, windowid = %{public}d, sessionId = %{public}ld, eventType = %{public}d,"
        "hookid = %{public}ld", asyncContext->event.windowId, asyncContext->event.sessionId,
        asyncContext->event.eventType, asyncContext->event.hookId);
    if (!SendControlEventExec(asyncContext)) {
        FI_HILOGE("send control event execution failed");
        delete asyncContext;
        return nullptr;
    }
    return promise;
}

bool OnScreenNapi::ConstructOnScreen(napi_env env, napi_value jsThis)
{
    if (g_onScreenObj == nullptr) {
        g_onScreenObj = new (std::nothrow) OnScreenNapi(env, jsThis);
        if (g_onScreenObj == nullptr) {
            FI_HILOGE("faild to get g_onScreenObj");
            return false;
        }
        napi_status status = napi_wrap(env, jsThis, reinterpret_cast<void *>(g_onScreenObj),
            [](napi_env env, void *data, void *hint) {
                (void)env;
                (void)hint;
                if (data != nullptr) {
                    OnScreenNapi *onScreen = reinterpret_cast<OnScreenNapi *>(data);
                    delete onScreen;
                }
            }, nullptr, nullptr);
        if (status != napi_ok) {
            delete g_onScreenObj;
            g_onScreenObj = nullptr;
            FI_HILOGE("napi_wrap failed");
            return false;
        }
    }
    return true;
}

bool OnScreenNapi::GetContentOption(napi_env env, napi_value *args, size_t argc, ContentOption &option)
{
    if (argc != ARG_1) {
        return false;
    }
    napi_value contentOptionObj = args[ARG_0];
    bool ret = GetInt32FromJs(env, contentOptionObj, "windowId", option.windowId, false);
    ret = ret && GetBoolFromJs(env, contentOptionObj, "contentUnderstand", option.contentUnderstand, false);
    ret = ret && GetBoolFromJs(env, contentOptionObj, "pageLink", option.pageLink, false);
    ret = ret && GetBoolFromJs(env, contentOptionObj, "textOnly", option.textOnly, false);
    ret = ret && GetInt32FromJs(env, contentOptionObj, "maxParagraphSize", option.maxParagraphSize, false);
    if (!ret) {
        FI_HILOGE("get content option failed");
    }
    return ret;
}

bool OnScreenNapi::GetControlEvent(napi_env env, napi_value *args, size_t argc, ControlEvent &event)
{
    if (argc != ARG_1) {
        return false;
    }
    napi_value eventObj = args[ARG_0];
    int32_t eventType = 0;
    bool ret = GetInt32FromJs(env, eventObj, "windowId", event.windowId, true);
    ret = ret && GetInt64FromJs(env, eventObj, "sessionId", event.sessionId, true);
    ret = ret && GetInt32FromJs(env, eventObj, "eventType", eventType, true);
    ret = ret && GetInt64FromJs(env, eventObj, "hookId", event.hookId, false);
    if (eventType <= static_cast<int32_t>(EventType::UNKNOWN) || eventType >= static_cast<int32_t>(EventType::END)) {
        FI_HILOGE("event type is invalid");
        return false;
    } else {
        event.eventType = static_cast<EventType>(eventType);
    }
    if (!ret) {
        FI_HILOGE("get control event failed");
    }
    return ret;
}

bool OnScreenNapi::GetInt32FromJs(napi_env env, const napi_value &value, const std::string &field,
    int32_t &result, bool isNecessary)
{
    bool hasProperty = false;
    if (napi_has_named_property(env, value, field.c_str(), &hasProperty) != napi_ok) {
        FI_HILOGE("napi_has_named_property failed");
        return false;
    }
    if (!hasProperty) {
        FI_HILOGW("napi dont have this property");
        // 如果是必要的，则返回false，如果不必要，则返回true，使用默认值
        return !isNecessary;
    }
    napi_value fieldValue = nullptr;
    napi_valuetype valueType = napi_undefined;
    if (napi_get_named_property(env, value, field.c_str(), &fieldValue) != napi_ok) {
        FI_HILOGE("napi_get_named_property failed");
        return false;
    }
    if (napi_typeof(env, fieldValue, &valueType) != napi_ok) {
        FI_HILOGE("typeof failed");
        return false;
    }
    if (valueType != napi_number) {
        FI_HILOGE("valueType is not number");
        return false;
    }
    if (napi_get_value_int32(env, fieldValue, &result) != napi_ok) {
        FI_HILOGE("napi_get_value_int32 failed");
        return false;
    }
    return true;  
}

bool OnScreenNapi::GetInt64FromJs(napi_env env, const napi_value &value, const std::string &field,
    int64_t &result, bool isNecessary)
{
    bool hasProperty = false;
    if (napi_has_named_property(env, value, field.c_str(), &hasProperty) != napi_ok) {
        FI_HILOGE("napi_has_named_property failed");
        return false;
    }
    if (!hasProperty) {
        FI_HILOGW("napi dont have this property");
        // 如果是必要的，则返回false，如果不必要，则返回true，使用默认值
        return !isNecessary;
    }
    napi_value fieldValue = nullptr;
    napi_valuetype valueType = napi_undefined;
    if (napi_get_named_property(env, value, field.c_str(), &fieldValue) != napi_ok) {
        FI_HILOGE("napi_get_named_property failed");
        return false;
    }
    if (napi_typeof(env, fieldValue, &valueType) != napi_ok) {
        FI_HILOGE("typeof failed");
        return false;
    }
    if (valueType != napi_number) {
        FI_HILOGE("valueType is not number");
        return false;
    }
    if (napi_get_value_int64(env, fieldValue, &result) != napi_ok) {
        FI_HILOGE("napi_get_value_int64 failed");
        return false;
    }
    return true;  
}

bool OnScreenNapi::GetBoolFromJs(napi_env env, const napi_value &value, const std::string &field,
    bool &result, bool isNecessary)
{
    bool hasProperty = false;
    if (napi_has_named_property(env, value, field.c_str(), &hasProperty) != napi_ok) {
        FI_HILOGE("napi_has_named_property failed");
        return false;
    }
    if (!hasProperty) {
        FI_HILOGW("napi dont have this property");
        // 如果是必要的，则返回false，如果不必要，则返回true，使用默认值
        return !isNecessary;
    }
    napi_value fieldValue = nullptr;
    napi_valuetype valueType = napi_undefined;
    if (napi_get_named_property(env, value, field.c_str(), &fieldValue) != napi_ok) {
        FI_HILOGE("napi_get_named_property failed");
        return false;
    }
    if (napi_typeof(env, fieldValue, &valueType) != napi_ok) {
        FI_HILOGE("typeof failed");
        return false;
    }
    if (valueType != napi_boolean) {
        FI_HILOGE("valueType is not bool");
        return false;
    }
    if (napi_get_value_bool(env, fieldValue, &result) != napi_ok) {
        FI_HILOGE("napi_get_value_bool failed");
        return false;
    }
    return true;  
}

bool OnScreenNapi::SetInt32Property(napi_env env, napi_value targetObj, int32_t value, const char *propName)
{
    napi_value prop = nullptr;
    napi_status ret = napi_create_int32(env, value, &prop);
    if (ret != napi_ok) {
        FI_HILOGE("napi_create_int32 failed");
        return false;
    }
    return SetPropertyName(env, targetObj, propName, prop);
}

bool OnScreenNapi::SetInt64Property(napi_env env, napi_value targetObj, int64_t value, const char *propName)
{
    napi_value prop = nullptr;
    napi_status ret = napi_create_int64(env, value, &prop);
    if (ret != napi_ok) {
        FI_HILOGE("napi_create_int64 failed");
        return false;
    }
    return SetPropertyName(env, targetObj, propName, prop);
}

bool OnScreenNapi::SetStringProperty(napi_env env, napi_value targetObj, const std::string &value,
    const char *propName)
{
    napi_value prop = nullptr;
    napi_status ret = napi_create_string_utf8(env, value.c_str(), value.size(), &prop);
    if (ret != napi_ok) {
        FI_HILOGE("napi_create_string_utf8 failed");
        return false;
    }
    return SetPropertyName(env, targetObj, propName, prop);
}

bool OnScreenNapi::ConstructParagraphObj(napi_env env, napi_value retObj, const Paragraph &value)
{
    retObj = nullptr;
    if (napi_create_object(env, &retObj) != napi_ok) {
        FI_HILOGE("create obj failed");
        return false;
    }
    bool ret = SetInt64Property(env, retObj, value.hookId, "hookId");
    ret = ret && SetStringProperty(env, retObj, value.title, "title");
    ret = ret && SetStringProperty(env, retObj, value.content, "text");
    if (!ret) {
        FI_HILOGE("create paragrah obj failed");
        return false;
    }
    return true;
}

bool OnScreenNapi::SetParagraphVecProperty(napi_env env, napi_value targetObj, const std::vector<Paragraph> paragraphs,
    const char *propName)
{
    napi_value paraArray = nullptr;
    if (napi_create_array(env, &paraArray) != napi_ok) {
        FI_HILOGE("failed to create array");
        return false;
    }
    for (size_t i = 0; i < paragraphs.size(); i++) {
        napi_value element = nullptr;
        if (!ConstructParagraphObj(env, element, paragraphs[i])) {
            FI_HILOGE("failed to create para, i = %{public}zu", i);
            return false;
        }
        if (napi_set_element(env, paraArray, i, element) != napi_ok) {
            FI_HILOGE("failed to set element, i = %{public}zu", i);
            return false;
        }
    }
    return true;
}

bool OnScreenNapi::SetPropertyName(napi_env env, napi_value targetObj, const char *propName, napi_value propValue)
{
    napi_status status = napi_set_named_property(env, targetObj, propName, propValue);
    if (status != napi_ok) {
        FI_HILOGE("Failed to set the name property");
        return false;
    }
    return true;
}

bool OnScreenNapi::GetPageContentExec(GetPageContentAsyncContext *asyncContext)
{
    CHKPF(asyncContext);
    CHKPF(asyncContext->env);
    CHKPF(asyncContext->deferred);
    napi_value resource = nullptr;
    std::string funcName = "getPageContentExec";
    napi_create_string_utf8(asyncContext->env, "getPageContentExec", funcName.size(), &resource);
    CHKRF(napi_create_async_work(asyncContext->env, nullptr, resource, GetPageContentExecCB,
        GetPageContentCompCB, static_cast<void*>(asyncContext), &asyncContext->work), "CREATE_ASYNC_WORK");
    CHKRF(napi_queue_async_work_with_qos(asyncContext->env, asyncContext->work, napi_qos_default), "QUEUE_ASYNC_WORK");
    FI_HILOGI("exec get page content succ");
    return true;
}

void OnScreenNapi::GetPageContentExecCB(napi_env env, void *data)
{
    CHKPV(data);
    CHKPV(env);
    std::lock_guard lockGuard(g_mtx);
    GetPageContentAsyncContext* execAsyncContext = static_cast<GetPageContentAsyncContext*>(data);
    execAsyncContext->result = OnScreenManager::GetInstance().GetPageContent(
        execAsyncContext->option, execAsyncContext->pageContent);
}

void OnScreenNapi::GetPageContentCompCB(napi_env env, napi_status status, void *data)
{
    CHKPV(data);
    CHKPV(env);
    std::lock_guard lockGrd(g_mtx);
    GetPageContentAsyncContext* completeAsyncContext = static_cast<GetPageContentAsyncContext*>(data);
    CHKPV(completeAsyncContext->deferred);
    napi_value errVal = nullptr;
    napi_value pageContentObj = nullptr;
    napi_status retStatus = napi_ok;
    if (napi_create_object(env, &pageContentObj) != napi_ok) {
        FI_HILOGE("pageContent failed");
        return;
    }
    bool ret = SetInt32Property(env, pageContentObj, completeAsyncContext->pageContent.windowId, "windowId");
    ret = ret && SetInt64Property(env, pageContentObj, completeAsyncContext->pageContent.sessionId, "sessionId");
    ret = ret && SetStringProperty(env, pageContentObj, completeAsyncContext->pageContent.bundleName, "bundleName");
    ret = ret && SetInt32Property(env, pageContentObj,
        static_cast<int32_t>(completeAsyncContext->pageContent.scenario), "scenario");
    ret = ret && SetStringProperty(env, pageContentObj, completeAsyncContext->pageContent.title, "title");
    ret = ret && SetStringProperty(env, pageContentObj, completeAsyncContext->pageContent.content, "content");
    ret = ret && SetStringProperty(env, pageContentObj, completeAsyncContext->pageContent.pageLink, "pageLink");
    ret = ret && SetParagraphVecProperty(env, pageContentObj, completeAsyncContext->pageContent.paragraphs, "paragraphs");
    if (!ret) {
        FI_HILOGE("construct page content failed");
        completeAsyncContext->result = RET_ERR;
    }
    if (completeAsyncContext->result != RET_OK) {
        auto retMsg = GetOnScreenErrMsg(completeAsyncContext->result);
        if (retMsg != std::nullopt) {
            ThrowOnScreenErrByPromise(env, completeAsyncContext->result, retMsg.value(), errVal);
        } else {
            ThrowOnScreenErrByPromise(env, SERVICE_EXCEPTION, "service exception", errVal);
        }
        retStatus = napi_reject_deferred(env, completeAsyncContext->deferred, errVal);
    } else {
        retStatus = napi_resolve_deferred(env, completeAsyncContext->deferred, pageContentObj);
    }
    if (retStatus != napi_ok) {
        FI_HILOGE("napi pack deferred err, result = %{public}d, status = %{public}d", completeAsyncContext->result,
            retStatus);
    }
    napi_delete_async_work(env, completeAsyncContext->work);
    delete completeAsyncContext;
    completeAsyncContext = nullptr;
}

bool OnScreenNapi::SendControlEventExec(SendControlEventAsyncContext *asyncContext)
{
    CHKPF(asyncContext);
    CHKPF(asyncContext->env);
    CHKPF(asyncContext->deferred);
    napi_value resource = nullptr;
    std::string funcName = "sendControlEventExec";
    napi_create_string_utf8(asyncContext->env, "sendControlEventExec", funcName.size(), &resource);
    CHKRF(napi_create_async_work(asyncContext->env, nullptr, resource, SendControlEventExecCB,
        SendControlEventCompCB, static_cast<void*>(asyncContext), &asyncContext->work), "CREATE_ASYNC_WORK");
    CHKRF(napi_queue_async_work_with_qos(asyncContext->env, asyncContext->work, napi_qos_default), "QUEUE_ASYNC_WORK");
    FI_HILOGI("exec send control event succ");
    return true;
}

void OnScreenNapi::SendControlEventExecCB(napi_env env, void *data)
{
    CHKPV(data);
    CHKPV(env);
    std::lock_guard lockGuard(g_mtx);
    SendControlEventAsyncContext* execAsyncContext = static_cast<SendControlEventAsyncContext*>(data);
    execAsyncContext->result = OnScreenManager::GetInstance().SendControlEvent(
        execAsyncContext->event);
}

void OnScreenNapi::SendControlEventCompCB(napi_env env, napi_status status, void *data)
{
    CHKPV(data);
    CHKPV(env);
    std::lock_guard lockGrd(g_mtx);
    SendControlEventAsyncContext* completeAsyncContext = static_cast<SendControlEventAsyncContext*>(data);
    CHKPV(completeAsyncContext->deferred);
    napi_value errVal = nullptr;
    napi_status retStatus = napi_ok;
    napi_value retVal = nullptr;
    if (napi_create_object(env, &retVal) != napi_ok) {
        FI_HILOGE("send control event create obj failed");
        return;
    }
    if (completeAsyncContext->result != RET_OK) {
        auto retMsg = GetOnScreenErrMsg(completeAsyncContext->result);
        if (retMsg != std::nullopt) {
            ThrowOnScreenErrByPromise(env, completeAsyncContext->result, retMsg.value(), errVal);
        } else {
            ThrowOnScreenErrByPromise(env, SERVICE_EXCEPTION, "service exception", errVal);
        }
        retStatus = napi_reject_deferred(env, completeAsyncContext->deferred, errVal);
    } else {
        retStatus = napi_resolve_deferred(env, completeAsyncContext->deferred, retVal);
    }
    if (retStatus != napi_ok) {
        FI_HILOGE("napi pack deferred err, result = %{public}d, status = %{public}d", completeAsyncContext->result,
            retStatus);
    }
    napi_delete_async_work(env, completeAsyncContext->work);
    delete completeAsyncContext;
    completeAsyncContext = nullptr;
}

EXTERN_C_START
/*
 * function for module exports
 */
static napi_value OnScreenNapiInit(napi_env env, napi_value exports)
{
    FI_HILOGD("Enter");
    napi_value ret = OnScreenNapi::Init(env, exports);
    if (ret == nullptr) {
        FI_HILOGE("Failed to init");
        return ret;
    }
    FI_HILOGD("Exit");
    return ret;
}
EXTERN_C_END

/*
 * Module definition
 */
static napi_module g_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = "multimodalAwareness.onScreen",
    .nm_register_func = OnScreenNapiInit,
    .nm_modname = "multimodalAwareness.onScreen",
    .nm_priv = (static_cast<void *>(nullptr)),
    .reserved = { nullptr }
};

/*
 * Module registration
 */
extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&g_module);
}
} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS