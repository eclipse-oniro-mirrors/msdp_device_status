/**
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

#include "screen_event_napi.h"

#include <mutex>

#include "devicestatus_define.h"
#include "fi_log.h"
#include "napi_constants.h"
#include "on_screen_manager.h"
#include "on_screen_napi_error.h"
#include "util_napi.h"

#undef LOG_TAG
#define LOG_TAG  "ScreenEventNapi"
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
namespace {
constexpr size_t ARG_0 = 0;
constexpr size_t ARG_1 = 1;
constexpr size_t ARG_2 = 2;
constexpr size_t ARG_3 = 3;
ScreenEventNapi *g_screenChangeObj = nullptr;
std::mutex g_mtx;
std::set<std::string> g_futuer;
constexpr size_t MAX_ARG_STR_LEN = 100;
std::unordered_map<int32_t, std::unordered_map<std::string, sptr<OnScreenCallback>>> g_screenCallbacks;
} // namespace

ScreenEventNapi::ScreenEventNapi(napi_env env, napi_value thisVar)
{
    env_ = env;
}

ScreenEventNapi::~ScreenEventNapi() {}

napi_value ScreenEventNapi::Init(napi_env env, napi_value exports)
{
    FI_HILOGD("Enter");
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_FUNCTION("registerScreenEvent", RegisterScreenEventCallbackNapi),
        DECLARE_NAPI_STATIC_FUNCTION("unregisterScreenEvent", UnregisterScreenEventCallbackNapi),
        DECLARE_NAPI_STATIC_FUNCTION("isParallelFeatureEnabled", IsParallelFeatureEnabled),
        DECLARE_NAPI_STATIC_FUNCTION("getLiveStatus", GetLiveStatus),
    };
    MSDP_CALL(napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    DefParallelFeatureStatus(env, exports);
    return exports;
}

void ScreenEventNapi::DefParallelFeatureStatus(napi_env env, napi_value exports)
{
    napi_value parallelFeatureStatus;
    napi_status status = napi_create_object(env, &parallelFeatureStatus);
    if (status != napi_ok) {
        FI_HILOGE("Failed create object");
        return;
    }
    SetInt32Property(env, parallelFeatureStatus,
        static_cast<int32_t>(ParallelFeatureStatus::DISABLED), "DISABLED");
    SetInt32Property(env, parallelFeatureStatus,
        static_cast<int32_t>(ParallelFeatureStatus::ENABLED), "ENABLED");
    SetPropertyName(env, exports, "ParallelFeatureStatus", parallelFeatureStatus);
}

OnScreenCallback::~OnScreenCallback()
{
    if (env_ == nullptr) {
        return;
    }
    for (auto ref : onRef) {
        napi_delete_reference(env_, ref);
    }
    onRef.clear();
}

void OnScreenCallback::OnScreenChange(const std::string& changeInfo)
{
    sptr<OnScreenCallback> self(this);
    std::vector<napi_ref> refSnapshot;
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        refSnapshot.assign(onRef.begin(), onRef.end());
    }

    auto task = [self, refs = std::move(refSnapshot), changeInfo]() {
        for (auto& item : refs) {
            napi_value handler = nullptr;
            {
                std::lock_guard<std::mutex> lk(g_mtx);
                if (self->onRef.find(item) == self->onRef.end()) {
                    continue;
                }
                if (napi_get_reference_value(self->env_, item, &handler) != napi_ok) {
                    FI_HILOGE("napi_get_reference_value failed");
                    return;
                }
            }
            napi_value result;
            if (napi_create_string_utf8(self->env_, changeInfo.c_str(), NAPI_AUTO_LENGTH, &result) != napi_ok) {
                FI_HILOGE("Failed to napi_create_string_utf8");
                continue;
            }
            FI_HILOGD("changeInfo: %{public}s", changeInfo.c_str());
            napi_value callResult = nullptr;
            napi_call_function(self->env_, nullptr, handler, 1, &result, &callResult);
        }
    };
    if (napi_send_event(self->env_, task, napi_eprio_immediate) != napi_ok) {
        FI_HILOGE("Failed to SendEvent");
    }
}

napi_value ScreenEventNapi::RegisterScreenEventCallbackNapi(napi_env env, napi_callback_info info)
{
    FI_HILOGD("Enter");
    size_t argc = 3;
    napi_value args[ARG_3] = { nullptr };
    napi_value jsThis = nullptr;
    napi_value result = nullptr;
    if (napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr) != napi_ok || argc != ARG_3) {
        ThrowOnScreenErr(env, RET_SERVICE_EXCEPTION, "napi_get_cb_info failed, expected 3 args");
        return nullptr;
    }

    // Get WindowId
    int32_t windowId = -1;
    if (!TransJsToInt32(env, args[ARG_0], windowId)) {
        ThrowOnScreenErr(env, RET_PARAM_ERR, "can not get windowId");
        return nullptr;
    }

    // Get Event
    std::string eventStr;
    if (!TransJsToStr(env, args[ARG_1], eventStr)) {
        ThrowOnScreenErr(env, RET_PARAM_ERR, "can not get event");
        return nullptr;
    }

    // Get Callback
    sptr<OnScreenCallback> callback = nullptr;
    napi_ref handlerRef = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        if (!ConstructScreenEventNapi(env, jsThis)) {
            ThrowOnScreenErr(env, RET_SERVICE_EXCEPTION, "Failed to get g_screenChangeobj");
            return nullptr;
        }

        if (napi_create_reference(env, args[ARG_2], 1, &handlerRef) != napi_ok) {
            ThrowOnScreenErr(env, RET_PARAM_ERR, "can not get callback");
            if (handlerRef != nullptr) {
                napi_delete_reference(env, handlerRef);
            }
            return nullptr;
        }
        callback = UpsertScreenCallback(env, windowId, eventStr, args[ARG_2], handlerRef);
    }

    if (callback != nullptr) {
        OnScreenManager::GetInstance().RegisterScreenEventCallback(windowId, eventStr, callback);
    } else {
        if (handlerRef != nullptr) {
            napi_delete_reference(env, handlerRef);
        }
        return nullptr;
    }
    napi_get_undefined(env, &result);
    return result;
}

bool ScreenEventNapi::ConstructScreenEventNapi(napi_env env, napi_value jsThis)
{
    if (g_screenChangeObj == nullptr) {
        g_screenChangeObj = new (std::nothrow) ScreenEventNapi(env, jsThis);
        if (g_screenChangeObj == nullptr) {
            FI_HILOGE("faild to get g_screenChangeObj");
            return false;
        }
        napi_status status = napi_wrap(env, jsThis, reinterpret_cast<void *>(g_screenChangeObj),
            [](napi_env env, void *data, void *hint) {
                (void)env;
                (void)hint;
                if (data != nullptr) {
                    ScreenEventNapi *screenChange = reinterpret_cast<ScreenEventNapi *>(data);
                    delete screenChange;
                }
            }, nullptr, nullptr);
        if (status != napi_ok) {
            delete g_screenChangeObj;
            g_screenChangeObj = nullptr;
            FI_HILOGE("napi_wrap failed");
            return false;
        }
    }
    return true;
}

bool ScreenEventNapi::TransJsToStr(napi_env env, napi_value in, std::string &out)
{
    FI_HILOGD("Enter");
    napi_valuetype type = napi_undefined;
    if (napi_typeof(env, in, &type) != napi_ok || type != napi_string) {
        FI_HILOGE("input is not a string");
        return false;
    }
    size_t strLen = 0;
    napi_status status = napi_get_value_string_utf8(env, in, nullptr, 0, &strLen);
    if (status != napi_ok) {
        FI_HILOGE("Error string length invalid");
        return false;
    }
    if (strLen > MAX_ARG_STR_LEN) {
        FI_HILOGE("The string length invalid");
        return false;
    }
    std::vector<char> buf(strLen + 1);
    status = napi_get_value_string_utf8(env, in, buf.data(), strLen+1, &strLen);
    if (status != napi_ok) {
        FI_HILOGE("napi_get_value_string_utf8 failed");
        return false;
    }
    out = buf.data();
    return true;
}

bool ScreenEventNapi::TransJsToInt32(napi_env env, napi_value in, int32_t &out)
{
    FI_HILOGD("Enter");
    napi_status status = napi_get_value_int32(env, in, &out);
    if (status != napi_ok) {
        FI_HILOGE("napi_get_value_int32 failed");
        return false;
    }
    return true;
}

// check whether a JS handler is already registered in refs
bool ScreenEventNapi::IsSameJsHandler(napi_env env, const std::set<napi_ref> &refs, napi_value jsHandler)
{
    for (auto ref : refs) {
        napi_value handler = nullptr;
        if (napi_get_reference_value(env, ref, &handler) != napi_ok) {
            continue;
        }
        bool same = false;
        if (napi_strict_equals(env, handler, jsHandler, &same) == napi_ok && same) {
            return true;
        }
    }
    return false;
}

// create/attach callback and update g_screenCallbacks; return nullptr when duplicate
sptr<OnScreenCallback> ScreenEventNapi::UpsertScreenCallback(
    napi_env env, int32_t windowId, const std::string &event, napi_value jsHandler, napi_ref handlerRef)
{
    FI_HILOGD("enter");
    sptr<OnScreenCallback> callback = nullptr;
    if (g_screenCallbacks.find(windowId) != g_screenCallbacks.end()) {
        auto& eventCallbacks = g_screenCallbacks[windowId];
        if (eventCallbacks.find(event) == eventCallbacks.end()) {
            callback = new (std::nothrow) OnScreenCallback(env);
            if (callback == nullptr) {
                FI_HILOGE("callback is nullptr");
                return nullptr;
            }
            callback->windowId = windowId;
            callback->event = event;
            callback->onRef.insert(handlerRef);
            eventCallbacks.emplace(event, callback);
        } else {
            auto& refs = eventCallbacks[event]->onRef;
            if (IsSameJsHandler(env, refs, jsHandler)) {
                return nullptr;
            }
            refs.insert(handlerRef);
        }
    } else {
        callback = new (std::nothrow) OnScreenCallback(env);
        if (callback == nullptr) {
            FI_HILOGE("callback is nullptr");
            return nullptr;
        }
        callback->windowId = windowId;
        callback->event = event;
        callback->onRef.insert(handlerRef);
        g_screenCallbacks[windowId].emplace(event, callback);
    }
    return callback;
}

// 0参：删除全部
void ScreenEventNapi::CollectAllPendingLocked(std::vector<PendingOff>& pending)
{
    std::lock_guard<std::mutex> lk(g_mtx);
    for (auto &wIt : g_screenCallbacks) {
        for (auto &eIt : wIt.second) {
            pending.push_back({ eIt.second->windowId, eIt.second->event, eIt.second });
        }
    }
    g_screenCallbacks.clear();
}

// 1参：删除某个 windowId 下全部
bool ScreenEventNapi::CollectWindowAllPendingLocked(int32_t windowId, std::vector<PendingOff>& pending)
{
    std::lock_guard<std::mutex> lk(g_mtx);
    auto wIt = g_screenCallbacks.find(windowId);
    if (wIt == g_screenCallbacks.end()) {
        return false;
    }
    for (auto &eIt : wIt->second) {
        pending.push_back({ eIt.second->windowId, eIt.second->event, eIt.second });
    }
    g_screenCallbacks.erase(wIt);
    return true;
}

// 2参：删除 (windowId, eventStr) 整个
bool ScreenEventNapi::CollectEventNodePendingLocked(int32_t windowId,
    const std::string& eventStr, std::vector<PendingOff>& pending)
{
    std::lock_guard<std::mutex> lk(g_mtx);
    auto wIt = g_screenCallbacks.find(windowId);
    if (wIt == g_screenCallbacks.end()) {
        return false;
    }
    auto eIt = wIt->second.find(eventStr);
    if (eIt == wIt->second.end()) {
        return false;
    }
    pending.push_back({ eIt->second->windowId, eIt->second->event, eIt->second });
    wIt->second.erase(eIt);
    if (wIt->second.empty()) g_screenCallbacks.erase(wIt);
    return true;
}

// 3参：删除 (windowId, eventStr, jsHandler) 指定回调
bool ScreenEventNapi::EraseOneHandlerLocked(int32_t windowId, const std::string& eventStr,
    napi_env env, napi_value jsHandler, std::vector<PendingOff>& pending)
{
    std::lock_guard<std::mutex> lk(g_mtx);
    auto wIt = g_screenCallbacks.find(windowId);
    if (wIt == g_screenCallbacks.end()) {
        return false;
    }

    auto eIt = wIt->second.find(eventStr);
    if (eIt == wIt->second.end()) {
        return false;
    }
    
    napi_env owner = eIt->second->env_;
    if (!EraseAndDeleteJsHandler(owner, eIt->second->onRef, jsHandler)) {
        return false;
    }
    if (eIt->second->onRef.empty()) {
        pending.push_back({ eIt->second->windowId, eIt->second->event, eIt->second });
        wIt->second.erase(eIt);
        if (wIt->second.empty()) g_screenCallbacks.erase(wIt);
    }
    return true;
}

napi_value ScreenEventNapi::UnregisterScreenEventCallbackNapi(napi_env env, napi_callback_info info)
{
    size_t argc = 3;
    napi_value args[3] = { nullptr, nullptr, nullptr };
    napi_value jsThis = nullptr;
    napi_value ret = nullptr;
    
    if (napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr) != napi_ok) {
        ThrowOnScreenErr(env, RET_SERVICE_EXCEPTION, "napi_get_cb_info failed");
        return nullptr;
    }

    std::vector<PendingOff> pending;
    // 0参：删除全部
    if (argc == ARG_0) {
        CollectAllPendingLocked(pending);
    } else {
        // get windowId
        int32_t windowId = -1;
        if (!TransJsToInt32(env, args[ARG_0], windowId)) {
            ThrowOnScreenErr(env, RET_PARAM_ERR, "can not get windowId");
            return nullptr;
        }

        // 1参：删除某个 windowId 下全部（第四个判定）
        if (argc == ARG_1) {
            if (!CollectWindowAllPendingLocked(windowId, pending)) { // 不存在时视为幂等，无需报错
                ThrowOnScreenErr(env, RET_PARAM_ERR, "can not get windowId");
                return nullptr;
            }
        } else {
            // get event
            std::string eventStr;
            if (!TransJsToStr(env, args[ARG_1], eventStr)) { // (4)
                ThrowOnScreenErr(env, RET_PARAM_ERR, "can not get event");
                return nullptr;
            }
            //  2参：删除 (win,event) 全部 否则 3参删除指定 handler（第五个判定）
            if (argc == ARG_2 && !CollectEventNodePendingLocked(windowId, eventStr, pending)) {
                ThrowOnScreenErr(env, RET_PARAM_ERR, "wrong param");
                return nullptr;
            }
            if (argc == ARG_3 && !EraseOneHandlerLocked(windowId, eventStr, env, args[ARG_2], pending)) {
                ThrowOnScreenErr(env, RET_PARAM_ERR, "wrong param");
                return nullptr;
            }
        }
    }

    // 锁外：逐条反注册
    for (const auto &item : pending) {
        OnScreenManager::GetInstance().UnregisterScreenEventCallback(item.wid, item.evt, item.cb);
    }

    napi_get_undefined(env, &ret);
    return ret;
}

napi_value ScreenEventNapi::IsParallelFeatureEnabled(napi_env env, napi_callback_info info)
{
    FI_HILOGD("Enter");
    size_t argc = 1;
    napi_value args[ARG_1] = { nullptr };
    napi_value jsThis = nullptr;
    if (napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr) != napi_ok) {
        ThrowOnScreenErr(env, RET_SERVICE_EXCEPTION, "napi_get_cb_info failed");
        return nullptr;
    }

    int32_t windowId = -1;
    if (argc < 1 || !TransJsToInt32(env, args[ARG_0], windowId)) {
        ThrowOnScreenErr(env, RET_PARAM_ERR, "can not get windowId");
        return nullptr;
    }

    int32_t res = static_cast<int32_t>(ParallelFeatureStatus::DISABLED);
    auto ret = OnScreenManager::GetInstance().IsParallelFeatureEnabled(windowId, res);
    if (ret != RET_OK) {
        FI_HILOGE("manager.IsParallelFeatureEnabled failed, ret=%{public}d", ret);
        ThrowOnScreenErr(env, RET_SERVICE_EXCEPTION, "IsParallelFeatureEnabled failed");
        return nullptr;
    }

    napi_value out;
    napi_create_int32(env, res, &out);
    return out;
}

napi_value ScreenEventNapi::GetLiveStatus(napi_env env, napi_callback_info info)
{
    FI_HILOGI("get live status");
    auto res = OnScreenManager::GetInstance().GetLiveStatus();
    napi_value out;
    napi_create_int32(env, res, &out);
    return out;
}

void ScreenEventNapi::SetInt32Property(napi_env env, napi_value targetObj, int32_t value, const char *propName)
{
    napi_value prop = nullptr;
    napi_status ret = napi_create_int32(env, value, &prop);
    if (ret != napi_ok) {
        FI_HILOGE("napi_create_int32 failed");
        return;
    }
    SetPropertyName(env, targetObj, propName, prop);
}
void ScreenEventNapi::SetPropertyName(napi_env env, napi_value targetObj, const char *propName, napi_value propValue)
{
    napi_status status = napi_set_named_property(env, targetObj, propName, propValue);
    if (status != napi_ok) {
        FI_HILOGE("Failed to set the name property");
        return;
    }
}
bool ScreenEventNapi::EraseAndDeleteJsHandler(napi_env env, std::set<napi_ref>& refs, napi_value jsHandler)
{
    for (auto it = refs.begin(); it != refs.end();) {
        napi_value cur = nullptr;
        if (napi_get_reference_value(env, *it, &cur) != napi_ok) {
            FI_HILOGE("napi_get_reference_value failed, skip on ref");
            ++it;
            continue;
        }
        bool same = false;
        if (napi_strict_equals(env, cur, jsHandler, &same) != napi_ok || !same) {
            ++it;
            continue;
        }
        napi_ref doomed = *it;
        it = refs.erase(it);
        if (napi_delete_reference(env, doomed) != napi_ok) {
            FI_HILOGE("napi_delete_reference failed after erase");
            return false;
        }
        return true;
    }
    return false;
}

EXTERN_C_START
/*
 * function for module exports
 */
static napi_value ScreenEventNapiInit(napi_env env, napi_value exports)
{
    FI_HILOGD("Enter");
    napi_value ret = ScreenEventNapi::Init(env, exports);
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
static napi_module ScreenEventModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = ScreenEventNapiInit,
    .nm_modname = "screenevent",
    .nm_priv = (static_cast<void *>(nullptr)),
    .reserved = { nullptr }
};

/*
 * Module registration
 */
extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&ScreenEventModule);
}
} // OnScreen
} // DeviceStatus
} // namespace Msdp
} // namespace OHOS