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
// 1) g_instancesMtx 仅保护 g_instances
// 2) g_callbacksMtx 仅保护 g_screenCallbacks（map 结构层面的增删查）
// 锁顺序约定：若必须同时涉及两者，必须先拿 g_instancesMtx，再拿 g_callbacksMtx；
// 且任何 mutex（包括回调对象内部锁）持有期间禁止调用 N-API，避免 GC/finalize 重入导致死锁。
std::mutex g_instancesMtx;
std::mutex g_callbacksMtx;

std::set<std::string> g_futuer;
constexpr size_t MAX_ARG_STR_LEN = 100;

// 每个 env 都会有独立的 exports/模块实例，因此回调表也需要按 env 维度隔离。
using EventMap = std::unordered_map<std::string, sptr<OnScreenCallback>>;
using WindowMap = std::unordered_map<int32_t, EventMap>;
std::unordered_map<napi_env, WindowMap> g_screenCallbacks;
// 每个 env 一份 native 实例（绑定在 exports 上），避免 worker / 主线程互相干扰。
std::unordered_map<napi_env, ScreenEventNapi*> g_instances;

} // namespace

ScreenEventNapi::ScreenEventNapi(napi_env env, napi_value thisVar)
{}

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

    // namespace 形式的接口：把 native 实例生命周期绑定到 exports（每个 env 一份）。
    // 这样能在 env 销毁时（finalize）做兜底清理，避免 SA 回调继续上报时触发跨 env/失效 env 的 N-API 调用。
    ConstructScreenEventNapi(env, exports);
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
    // 析构仅清理本地容器；napi_ref 的释放由 CloseOnJsThread 在 JS 线程执行。
    std::lock_guard<std::mutex> lk(refMtx_);
    onRef_.clear();
}

void OnScreenCallback::SnapshotRefsLocked(std::vector<napi_ref> &out) const
{
    std::lock_guard<std::mutex> lk(refMtx_);
    out.assign(onRef_.begin(), onRef_.end());
}

bool OnScreenCallback::ContainsRefLocked(napi_ref ref) const
{
    std::lock_guard<std::mutex> lk(refMtx_);
    return onRef_.find(ref) != onRef_.end();
}

void OnScreenCallback::AddRefLocked(napi_ref ref)
{
    std::lock_guard<std::mutex> lk(refMtx_);
    onRef_.insert(ref);
}

bool OnScreenCallback::RemoveRefLocked(napi_ref ref)
{
    std::lock_guard<std::mutex> lk(refMtx_);
    return onRef_.erase(ref) > 0;
}

bool OnScreenCallback::EmptyLocked() const
{
    std::lock_guard<std::mutex> lk(refMtx_);
    return onRef_.empty();
}

// 在js线程中中执行napi_delete_reference
void OnScreenCallback::CloseOnJsThread()
{
    FI_HILOGI("Close Enter");
    if (env_ == nullptr) {
        return;
    }

    std::vector<napi_ref> refs;
    {
        std::lock_guard<std::mutex> lk(refMtx_);
        refs.assign(onRef_.begin(), onRef_.end());
        onRef_.clear();
    }
    //CloseOnJsThread 可能在 finalize/非 JS 线程被调用；
    // 因此这里不能直接调用任何 N-API（例如 napi_delete_reference），切回 JS 线程执行。
    if (refs.empty()) {
        return;
    }

    // 只捕获 env_/refs 的副本：
    // - refs 已从 onRef_ 中摘除（避免后续回调继续使用）
    // - JS 线程执行时做真正的 napi_delete_reference
    auto env = env_;
    auto task = [env, refs = std::move(refs)]() mutable {
        for (auto ref : refs) {
            napi_delete_reference(env, ref);
        }
    };
    // 若 env 正在销毁导致投递失败，则放弃删除（避免在非 JS 线程/失效 env 触发崩溃）。
    if (napi_send_event(env, task, napi_eprio_immediate, "screen.close") != napi_ok) {
        FI_HILOGE("CloseOnJsThread: napi_send_event failed, skip deleting refs");
    }
}

void OnScreenCallback::Disable()
{
    disabled_.store(true);
}

bool OnScreenCallback::Disabled()
{
    return disabled_.load();
}

void OnScreenCallback::OnScreenChange(const std::string& changeInfo)
{
    if (Disabled()) {
        FI_HILOGI("callback Disabled");
        return;
    }

    sptr<OnScreenCallback> self(this);
    std::vector<napi_ref> refSnapshot;
    SnapshotRefsLocked(refSnapshot);

    auto task = [self, refs = std::move(refSnapshot), changeInfo]() {
        for (auto& item : refs) {
            napi_value handler = nullptr;
            // 先做纯 C++ 判定，确保不要在持任何 mutex 时调用 N-API。
            if (self->Disabled() || !self->ContainsRefLocked(item)) {
                continue;
            }
            if (napi_get_reference_value(self->env_, item, &handler) != napi_ok) {
                FI_HILOGE("napi_get_reference_value failed");
                continue;
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
    if (napi_send_event(self->env_, task, napi_eprio_immediate, "screen.changed") != napi_ok) {
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
    if (napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr) != napi_ok || argc < ARG_3) {
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

    // 锁顺序：如需同时涉及 instances/callbacks，必须先 instances 再 callbacks。
    {
        std::lock_guard<std::mutex> lk(g_instancesMtx);
        if (g_instances.find(env) == g_instances.end()) {
            ThrowOnScreenErr(env, RET_SERVICE_EXCEPTION, "module not initialized");
            return nullptr;
        }
    }

    // N-API 调用必须在锁外。
    napi_ref handlerRef = nullptr;
    if (napi_create_reference(env, args[ARG_2], 1, &handlerRef) != napi_ok) {
        ThrowOnScreenErr(env, RET_PARAM_ERR, "can not get callback");
        return nullptr;
    }

    sptr<OnScreenCallback> needRegisterCb = nullptr;
    bool needRegisterSa = false;
    if (!UpsertScreenCallback(env, windowId, eventStr, args[ARG_2], handlerRef, needRegisterCb, needRegisterSa)) {
        napi_delete_reference(env, handlerRef);
        return nullptr;
    }
    if (needRegisterSa && needRegisterCb != nullptr) {
        OnScreenManager::GetInstance().RegisterScreenEventCallback(windowId, eventStr, needRegisterCb);
    }

    napi_get_undefined(env, &result);
    return result;
}

bool ScreenEventNapi::ConstructScreenEventNapi(napi_env env, napi_value holderObj)
{
    // 只负责在 Init 阶段把实例 wrap 到 exports；订阅/取消订阅不会触发 wrap。
    {
        std::lock_guard<std::mutex> lk(g_instancesMtx);
        if (g_instances.find(env) != g_instances.end()) {
            FI_HILOGI("env has find");
            return true;
        }
    }

    // holderObj 建议传 exports（模块导出对象），用于将 native 实例生命周期绑定到当前 env。
    ScreenEventNapi *inst = new (std::nothrow) ScreenEventNapi(env, holderObj);
    if (inst == nullptr) {
        FI_HILOGE("failed to new ScreenEventNapi");
        return false;
    }

    napi_status status = napi_wrap(env, holderObj, reinterpret_cast<void *>(inst),
        [](napi_env env, void *data, void *hint) {
            (void)hint;
            if (data == nullptr) {
                FI_HILOGE("data is nullptr");
                return;
            }
            auto *screenChange = reinterpret_cast<ScreenEventNapi *>(data);

            // exports 对象被 GC / env 即将销毁：这里做一次兜底清理（仅清理本 env）。
            // 1) 禁用并摘除所有订阅（纯 C++ 操作，防止后续回调继续触发 N-API）
            // 2) 反注册 SA 回调（停止上报）
            // 3) 在 JS 线程释放 napi_ref（CloseOnJsThread 内部发送到js线程调用 napi_delete_reference）
            std::vector<PendingOff> pending;
            ScreenEventNapi::CollectAllPendingLocked(env, pending);
            for (const auto &item : pending) {
                OnScreenManager::GetInstance().UnregisterScreenEventCallback(item.wid, item.evt, item.cb);
            }
            for (const auto &item : pending) {
                if (item.cb) {
                    item.cb->CloseOnJsThread();
                }
            }

            // 移除该 env 的实例，避免悬空。
            {
                std::lock_guard<std::mutex> lk(g_instancesMtx);
                auto it = g_instances.find(env);
                if (it != g_instances.end() && it->second == screenChange) {
                    g_instances.erase(it);
                }
            }
            delete screenChange;
        }, nullptr, nullptr);
    if (status != napi_ok) {
        delete inst;
        FI_HILOGE("napi_wrap failed");
        return false;
    }
    {
        std::lock_guard<std::mutex> lk(g_instancesMtx);
        g_instances.emplace(env, inst);
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
bool ScreenEventNapi::IsSameJsHandler(napi_env env, const std::vector<napi_ref> &refs, napi_value jsHandler)
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

// - false: 失败（OOM/重复等），调用方需删除 handlerRef
// - true : 成功；needRegisterSa=true 表示首次创建该(win,event)节点，需要向 SA Register。
bool ScreenEventNapi::UpsertScreenCallback(napi_env env, int32_t windowId, const std::string &event,
    napi_value jsHandler, napi_ref handlerRef, sptr<OnScreenCallback> &outCb, bool &needRegisterSa)
{
    FI_HILOGD("enter");
    outCb = nullptr;
    needRegisterSa = false;

    sptr<OnScreenCallback> existing = nullptr;
    std::vector<napi_ref> refsSnapshot;

    // 锁内仅进行 map 读写/快照，禁止任何 N-API。
    {
        std::lock_guard<std::mutex> lk(g_callbacksMtx);
        auto &envMap = g_screenCallbacks[env];
        auto &eventCallbacks = envMap[windowId];
        auto it = eventCallbacks.find(event);
        if (it == eventCallbacks.end() || it->second == nullptr || it->second->Disabled()) {
            sptr<OnScreenCallback> callback = new (std::nothrow) OnScreenCallback(env);
            if (callback == nullptr) {
                FI_HILOGE("map: callback is nullptr");
                return false;
            }
            callback->windowId = windowId;
            callback->event = event;
            callback->AddRefLocked(handlerRef);
            eventCallbacks[event] = callback;
            outCb = callback;
            needRegisterSa = true;
            return true;
        }
        existing = it->second;
        existing->SnapshotRefsLocked(refsSnapshot);
    }

    // 锁外做重复 handler 判定（N-API 调用）
    if (IsSameJsHandler(env, refsSnapshot, jsHandler)) {
        FI_HILOGI("js handler is same");
        return false;
    }

    // 重新入锁写入（期间可能已被清理/替换，需要再次校验）
    {
        std::lock_guard<std::mutex> lk(g_callbacksMtx);
        auto itEnv = g_screenCallbacks.find(env);
        if (itEnv == g_screenCallbacks.end()) {
            auto &envMap = g_screenCallbacks[env];
            auto &eventCallbacks = envMap[windowId];
            sptr<OnScreenCallback> callback = new (std::nothrow) OnScreenCallback(env);
            if (callback == nullptr) {
                FI_HILOGE("1.callback is nullptr");
                return false;
            }
            callback->windowId = windowId;
            callback->event = event;
            callback->AddRefLocked(handlerRef);
            eventCallbacks[event] = callback;
            outCb = callback;
            needRegisterSa = true;
            return true;
        }
        auto wIt = itEnv->second.find(windowId);
        if (wIt == itEnv->second.end()) {
            auto &eventCallbacks = itEnv->second[windowId];
            sptr<OnScreenCallback> callback = new (std::nothrow) OnScreenCallback(env);
            if (callback == nullptr) {
                FI_HILOGE("2.callback is nullptr");
                return false;
            }
            callback->windowId = windowId;
            callback->event = event;
            callback->AddRefLocked(handlerRef);
            eventCallbacks[event] = callback;
            outCb = callback;
            needRegisterSa = true;
            return true;
        }
        auto eIt = wIt->second.find(event);
        if (eIt == wIt->second.end() || eIt->second == nullptr || eIt->second->Disabled()) {
            sptr<OnScreenCallback> callback = new (std::nothrow) OnScreenCallback(env);
            if (callback == nullptr) {
                FI_HILOGE("3.callback is nullptr");
                return false;
            }
            callback->windowId = windowId;
            callback->event = event;
            callback->AddRefLocked(handlerRef);
            wIt->second[event] = callback;
            outCb = callback;
            needRegisterSa = true;
            return true;
        }
        eIt->second->AddRefLocked(handlerRef);
    }
    return true;
}

// 0参：删除全部
void ScreenEventNapi::CollectAllPendingLocked(napi_env env,
    std::vector<PendingOff>& pending)
{
    std::lock_guard<std::mutex> lk(g_callbacksMtx);
    auto itEnv = g_screenCallbacks.find(env);
    if (itEnv == g_screenCallbacks.end()) {
        FI_HILOGE("env not find");
        return;
    }
    for (auto &wIt : itEnv->second) {
        for (auto &eIt : wIt.second) {
            if (eIt.second) {
                eIt.second->Disable(); // 标记停用
                pending.push_back({ eIt.second->windowId, eIt.second->event, eIt.second });
            }
        }
    }
    g_screenCallbacks.erase(itEnv);
}

// 1参：删除某个 windowId 下全部
bool ScreenEventNapi::CollectWindowAllPendingLocked(napi_env env, int32_t windowId,
    std::vector<PendingOff>& pending)
{
    std::lock_guard<std::mutex> lk(g_callbacksMtx);
    auto itEnv = g_screenCallbacks.find(env);
    if (itEnv == g_screenCallbacks.end()) {
        FI_HILOGE("env not find");
        return false;
    }
    auto wIt = itEnv->second.find(windowId);
    if (wIt == itEnv->second.end()) {
        FI_HILOGE("windowid: %{public}d not find", windowId);
        return false;
    }
    for (auto &eIt : wIt->second) {
        if (eIt.second) {
            eIt.second->Disable(); // 标记停用
            pending.push_back({ eIt.second->windowId, eIt.second->event, eIt.second });
        }
    }
    itEnv->second.erase(wIt);
    if (itEnv->second.empty()) {
        FI_HILOGI("erase callback");
        g_screenCallbacks.erase(itEnv);
    }
    return true;
}

// 2参：删除 (windowId, eventStr) 整个
bool ScreenEventNapi::CollectEventNodePendingLocked(napi_env env, int32_t windowId,
    const std::string& eventStr, std::vector<PendingOff>& pending)
{
    std::lock_guard<std::mutex> lk(g_callbacksMtx);
    auto itEnv = g_screenCallbacks.find(env);
    if (itEnv == g_screenCallbacks.end()) {
        FI_HILOGE("env not find");
        return false;
    }
    auto wIt = itEnv->second.find(windowId);
    if (wIt == itEnv->second.end()) {
        FI_HILOGE("windowid: %{public}d not find", windowId);
        return false;
    }
    auto eIt = wIt->second.find(eventStr);
    if (eIt == wIt->second.end()) {
        FI_HILOGE("eventStr: %{public}s not find", eventStr.c_str());
        return false;
    }

    if (eIt->second) {
        eIt->second->Disable(); // 标记停用
        pending.push_back({ eIt->second->windowId, eIt->second->event, eIt->second });
    }
    wIt->second.erase(eIt);
    if (wIt->second.empty()) {
        itEnv->second.erase(wIt);
        if (itEnv->second.empty()) {
            FI_HILOGI("erase callback");
            g_screenCallbacks.erase(itEnv);
        }
    }
    return true;
}

// 3参：删除 (windowId, eventStr, jsHandler) 指定回调
// 输出参数doomRefs, 把需要删除的napi_ref交给外层的js线程统一删除
bool ScreenEventNapi::EraseOneHandlerLocked(napi_env env, int32_t windowId, const std::string& eventStr,
    napi_value jsHandler, std::vector<PendingOff>& pending, std::vector<napi_ref>& doomedRefs)
{
    // 阶段 1：锁内只定位节点（禁用 N-API）
    sptr<OnScreenCallback> cb = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_callbacksMtx);
        auto itEnv = g_screenCallbacks.find(env);
        if (itEnv == g_screenCallbacks.end()) {
            FI_HILOGE("env not find");
            return false;
        }
        auto wIt = itEnv->second.find(windowId);
        if (wIt == itEnv->second.end()) {
            FI_HILOGE("windowid: %{public}d not find", windowId);
            return false;
        }
        auto eIt = wIt->second.find(eventStr);
        if (eIt == wIt->second.end() || eIt->second == nullptr) {
            FI_HILOGE("eventStr: %{public}s not find", eventStr.c_str());
            return false;
        }
        cb = eIt->second;
    }

    // 阶段 2：锁外做 jsHandler 匹配（N-API）并从集合中移除对应 ref
    napi_ref doomed = nullptr;
    if (!FindAndEraseJsHandler(env, cb, jsHandler, doomed)) {
        FI_HILOGE("Not find doomed");
        return false;
    }
    if (doomed != nullptr) {
        doomedRefs.push_back(doomed); // 暂存，外层 JS 线程统一 delete_reference
    }

    // 阶段 3：若该节点已无任何 handler，则锁内摘除并加入 pending
    {
        std::lock_guard<std::mutex> lk(g_callbacksMtx);
        auto itEnv = g_screenCallbacks.find(env);
        if (itEnv == g_screenCallbacks.end()) {
            return true;
        }
        auto wIt = itEnv->second.find(windowId);
        if (wIt == itEnv->second.end()) {
            return true;
        }
        auto eIt = wIt->second.find(eventStr);
        if (eIt == wIt->second.end() || eIt->second != cb) {
            return true;
        }
        if (cb->EmptyLocked()) {
            cb->Disable();
            pending.push_back({ cb->windowId, cb->event, cb });
            wIt->second.erase(eIt);
            if (wIt->second.empty()) {
                itEnv->second.erase(wIt);
                if (itEnv->second.empty()) {
                    FI_HILOGI("erase callback");
                    g_screenCallbacks.erase(itEnv);
                }
            }
        }
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
    std::vector<napi_ref> doomedRefs;
    // 0参：删除全部
    if (argc == ARG_0) {
        CollectAllPendingLocked(env, pending);
    } else {
        // get windowId
        int32_t windowId = -1;
        if (!TransJsToInt32(env, args[ARG_0], windowId)) {
            ThrowOnScreenErr(env, RET_PARAM_ERR, "can not get windowId");
            return nullptr;
        }

        // 1参：删除某个 windowId 下全部（第四个判定）
        if (argc == ARG_1) {
            if (!CollectWindowAllPendingLocked(env, windowId, pending)) { // 不存在时视为幂等，无需报错
                ThrowOnScreenErr(env, RET_PARAM_ERR, "can not get windowId");
                return nullptr;
            }
        } else {
            // get event
            std::string eventStr;
            if (!TransJsToStr(env, args[ARG_1], eventStr)) {
                ThrowOnScreenErr(env, RET_PARAM_ERR, "can not get event");
                return nullptr;
            }
            //  2参：删除 (win,event) 全部 否则 3参删除指定 handler（第五个判定）
            if (argc == ARG_2 && !CollectEventNodePendingLocked(env, windowId, eventStr, pending)) {
                ThrowOnScreenErr(env, RET_PARAM_ERR, "wrong param 2");
                return nullptr;
            }
            if (argc == ARG_3 && !EraseOneHandlerLocked(env, windowId, eventStr, args[ARG_2], pending, doomedRefs)) {
                ThrowOnScreenErr(env, RET_PARAM_ERR, "wrong param 3");
                return nullptr;
            }
        }
    }

    // 顺序：先反注册 -> 再删引用（都在 JS 线程调用本函数)
    // 先底层反注册
    for (const auto &item : pending) {
        OnScreenManager::GetInstance().UnregisterScreenEventCallback(item.wid, item.evt, item.cb);
    }

    // 删除仅handler的 napi_ref（JS 线程）
    for (auto ref : doomedRefs) {
        napi_delete_reference(env, ref);
    }

    // 关闭整节点/全部的 JS 资源（JS 线程）
    for (const auto &item : pending) {
        if (item.cb) {
            item.cb->CloseOnJsThread();
        }
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
            FI_HILOGE("napi_get_reference_value failed, skip one ref");
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

// 锁内只找删除某个handler，对应napi_ref通过doomed 返回;不删除引用
bool ScreenEventNapi::FindAndEraseJsHandler(napi_env env, const sptr<OnScreenCallback> &cb,
    napi_value jsHandler, napi_ref& doomed)
{
    // 在不持有任何 mutex 的情况下完成：
    // 1) 快照 refs（纯 C++）
    // 2) 锁外通过 N-API 做 strict_equals 找到匹配的 ref
    // 3) 纯 C++ 从集合中移除该 ref（不调用 napi_delete_reference）
    doomed = nullptr;
    if (cb == nullptr) {
        FI_HILOGE("cb is nullptr");
        return false;
    }
    std::vector<napi_ref> refsSnapshot;
    cb->SnapshotRefsLocked(refsSnapshot);
    for (auto ref : refsSnapshot) {
        napi_value cur = nullptr;
        if (napi_get_reference_value(env, ref, &cur) != napi_ok) {
            continue;
        }
        bool same = false;
        if (napi_strict_equals(env, cur, jsHandler, &same) == napi_ok && same) {
            doomed = ref;
            break;
        }
    }
    if (doomed == nullptr) {
        FI_HILOGE("doomed is nullptr");
        return false;
    }
    cb->RemoveRefLocked(doomed);
    return true;
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