/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "motion_napi.h"

#include <algorithm>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <unordered_set>

#include "devicestatus_define.h"
#include "fi_log.h"
#ifdef MOTION_ENABLE
#include "motion_client.h"
#include "napi_event_utils.h"
#endif
#include "motion_napi_error.h"

#undef LOG_TAG
#define LOG_TAG "DeviceMotionNapi"

namespace OHOS {
namespace Msdp {
namespace {
#ifdef MOTION_ENABLE
auto &g_motionClient = MotionClient::GetInstance();
constexpr int32_t PERMISSION_DENIED = 201;
static constexpr uint8_t ARG_1 = 1;
constexpr int32_t HOLDING_HAND_FEATURE_DISABLE = 11;
constexpr int32_t EVENT_NOT_SUPPORT = -200;
constexpr int32_t EVENT_NO_INITIALIZE = -1;
static int64_t processorId = -1;
#endif

static constexpr uint8_t ARG_0 = 0;
static constexpr uint8_t ARG_2 = 2;
constexpr int32_t INVALID_MOTION_TYPE = -1;
constexpr size_t MAX_ARG_STRING_LEN = 512;
constexpr int32_t MOTION_TYPE_OPERATING_HAND = 3601;
constexpr int32_t MOTION_TYPE_STAND = 3602;
constexpr int32_t MOTION_TYPE_REMOTE_PHOTO = 3604;
constexpr int32_t MOTION_TYPE_HOLDING_HAND_STATUS = 3605;
constexpr int32_t BASE_HAND = 0;
constexpr int32_t LEFT_HAND = 1;
constexpr int32_t RIGHT_HAND = 2;
enum HoldPostureStatus : int32_t {
    NOT_HELD = 0,
    LEFT_HAND_HELD,
    RIGHT_HAND_HELD,
    BOTH_HAND_HELD,
    UNKNOWN = 16,
};
const std::vector<std::string> EXPECTED_SUB_ARG_TYPES = { "string", "function" };
const std::vector<std::string> EXPECTED_UNSUB_ONE_ARG_TYPES = { "string" };
const std::vector<std::string> EXPECTED_UNSUB_TWO_ARG_TYPES = { "string", "function" };
const std::map<const std::string, int32_t> MOTION_TYPE_MAP = {
    { "operatingHandChanged", MOTION_TYPE_OPERATING_HAND },
    { "steadyStandingDetect", MOTION_TYPE_STAND },
    { "remotePhotoStandingDetect", MOTION_TYPE_REMOTE_PHOTO },
    { "holdingHandChanged", MOTION_TYPE_HOLDING_HAND_STATUS },
};
std::mutex g_instancesMutex;
std::unordered_map<napi_env, std::weak_ptr<MotionNapi>> g_instances;
std::mutex g_exportsMutex;
std::unordered_map<napi_env, napi_ref> g_exportsRefs;

#ifdef MOTION_ENABLE
  std::mutex g_callbacksMutex;
  std::unordered_map<int32_t, sptr<MotionCallback>> g_typeCallbacks;
#endif
} // namespace

#ifdef MOTION_ENABLE
void MotionCallback::AddTarget(const std::shared_ptr<MotionNapi>& target)
{
    FI_HILOGD("Enter");
    if (!target) {
        return;
    }
    // 在锁内对 targets_ 做一次“清理 + 去重压缩” 1) 清理 expired weak_ptr，避免 targets_ 越来越大；
    // 2) 消除历史重复项：3) 最后确保当前 target 一定被加入（若之前不存在）。
    std::lock_guard<std::mutex> lk(mutex_);
    std::unordered_set<MotionNapi*> uniq;
    uniq.reserve(targets_.size() + 1);
    std::vector<std::weak_ptr<MotionNapi>> compact;
    compact.reserve(targets_.size() + 1);
    bool exists = false;
    for (auto &w : targets_) {
        auto sp = w.lock();
        if (!sp) {
            continue; // 清理 expired
        }
        MotionNapi* key = sp.get();
        if (!uniq.insert(key).second) {
            continue; // 去重：相同对象只保留第一次
        }
        if (key == target.get()) {
            exists = true;
        }
        compact.push_back(sp); // shared_ptr -> weak_ptr
    }
    if (!exists) {
        compact.push_back(target);
    }
    targets_.swap(compact);
}

void MotionCallback::RemoveTarget(const std::shared_ptr<MotionNapi>& target)
{
    FI_HILOGD("Enter");
    if (!target) {
        FI_HILOGE("target is null");
        return;
    }
    std::lock_guard<std::mutex> lk(mutex_);
    targets_.erase(std::remove_if(targets_.begin(), targets_.end(),
        [&target](const std::weak_ptr<MotionNapi>& it) {
            auto sp = it.lock();
            return !sp || sp.get() == target.get();
        }), targets_.end());
}

bool MotionCallback::HasTargets() const
{
    std::lock_guard<std::mutex> lk(mutex_);
    for (auto &it : targets_) {
        if (!it.expired()) {
            return true;
        }
    }
    return false;
}

void MotionCallback::OnMotionChanged(const MotionEvent &event)
{
    FI_HILOGD("Enter");
    // 对每个 JS 上下文，调用 MotionNapi::PostMotionEvent() 投递回对应 JS 线程。(从service/binder线程)
    std::vector<std::shared_ptr<MotionNapi>> snapshot;
    {
        std::lock_guard<std::mutex> lk(mutex_);
        for (auto it = targets_.begin(); it != targets_.end();) {
            auto sp = it->lock();
            if (!sp) {
                it = targets_.erase(it);
                continue;
            }
            snapshot.push_back(std::move(sp));
            ++it;
        }
    }

    // 锁外去重，避免极端情况下 targets_ 中存在重复 weak_ptr
    std::unordered_set<MotionNapi*> seen;
    seen.reserve(snapshot.size());
    std::vector<std::shared_ptr<MotionNapi>> uniqueTargets;
    uniqueTargets.reserve(snapshot.size());
    for (auto &t : snapshot) {
        if (!t) {
            continue;
        }
        if (seen.insert(t.get()).second) {
            uniqueTargets.push_back(std::move(t));
        }
    }

    for (auto &tmp : uniqueTargets) {
        tmp->PostMotionEvent(event.type, event.status);
    }
    FI_HILOGD("Exit");
}
#endif

MotionNapi::MotionNapi(napi_env env, napi_value thisVar) : MotionEventNapi(env, thisVar)
{
    env_ = env;
}

MotionNapi::~MotionNapi()
{
#ifdef MOTION_ENABLE
    // 确保ts上下文销毁时，从回调里解绑，必要时取消 MotionClient 的系统订阅。
    UnsubscribeFromAllTypesNoThrow();
#endif
}

int32_t MotionNapi::GetMotionType(const std::string &type)
{
    FI_HILOGD("Enter");
    auto iter = MOTION_TYPE_MAP.find(type);
    if (iter == MOTION_TYPE_MAP.end()) {
        FI_HILOGD("Don't find this type");
        return INVALID_MOTION_TYPE;
    }
    FI_HILOGD("Exit");
    return iter->second;
}

#ifdef MOTION_ENABLE
bool MotionNapi::SubscribeToService(napi_env env, int32_t type, bool &serviceAlreadySubscribed)
{
    FI_HILOGD("Enter");
    // 同一个 motion type 在进程内只向 MotionClient 订阅一次，然后分发给多个 napi_env。
    // 1) g_callbacksMutex 只保护 g_typeCallbacks 读写，不在持锁状态下进行 IPC调用。
    // 2) MotionCallback::mutex_ 保护 targets_。锁顺序固定为：g_callbacksMutex -> mutex_
    sptr<MotionCallback> cb;
    serviceAlreadySubscribed = false;
    bool needIpcSubscribe = false; // 是否需要调用ipc
    // 锁内写g_typeCallbacks,锁外调用
    {
        std::lock_guard<std::mutex> lk(g_callbacksMutex);
        auto it = g_typeCallbacks.find(type);
        if (it != g_typeCallbacks.end()) {
            cb = it->second;
            serviceAlreadySubscribed = true;
        } else {
            cb = new (std::nothrow) MotionCallback();
            if (cb == nullptr) {
                FI_HILOGE("Failed to create MotionCallback");
                ThrowMotionErr(env, SUBSCRIBE_EXCEPTION, "Subscribe failed");
                return false;
            }

            // 先占坑，防止并发线程重复对同一 type 做 SubscribeCallback（避免重复订阅）
            g_typeCallbacks.emplace(type, cb);
            needIpcSubscribe = true;
        }
    }

    // AddTarget 放在锁外，避免 g_callbacksMutex 与 mutex_ 长时间叠加
    cb->AddTarget(shared_from_this());

    // IPC 调用放在锁外（锁安全增强关键点）
    bool res = true;
    if (needIpcSubscribe) {
        res = DoSubscription(env, type, cb);
    }
    return res;
}

bool MotionNapi::DoSubscription(napi_env env, int32_t type, sptr<MotionCallback> cb)
{
    // 避免并发竞态，持锁执行一次IPC订阅，确保订阅原子操作。
    int32_t ret = g_motionClient.SubscribeCallback(type, cb);
    if (ret != RET_OK) {
        // 回滚：移除 target + 从 map 中移除占坑项（仅当仍指向同一个 cb）
        cb->RemoveTarget(shared_from_this());
        {
            std::lock_guard<std::mutex> lk(g_callbacksMutex);
            auto it = g_typeCallbacks.find(type);
            if (it != g_typeCallbacks.end() && it->second == cb) {
                g_typeCallbacks.erase(it);
            }
        }

        if (ret == PERMISSION_DENIED) {
            FI_HILOGE("Failed to subscribe");
            ThrowMotionErr(env, PERMISSION_EXCEPTION, "Permission denined");
            return false;
        } else if (ret == DEVICE_EXCEPTION || ret == HOLDING_HAND_FEATURE_DISABLE) {
            FI_HILOGE("Failed to subscribe");
            ThrowMotionErr(env, DEVICE_EXCEPTION, "Device not support");
            return false;
        } else {
            FI_HILOGE("Failed to subscribe");
            ThrowMotionErr(env, SUBSCRIBE_EXCEPTION, "Subscribe failed");
            return false;
        }
    }
    return true;
}

bool MotionNapi::UnsubscribeFromService(napi_env env, int32_t type)
{
    FI_HILOGD("Enter");
    // CheckEvents(type) == true 时调用
    // g_callbacksMutex 保护 map 操作；IPC（UnsubscribeCallback）在锁外执行
    // 最后一个 target 才真正对 service 做 unsubscribe
    sptr<MotionCallback> cb;
    {
        std::lock_guard<std::mutex> lk(g_callbacksMutex);
        auto it = g_typeCallbacks.find(type);
        if (it == g_typeCallbacks.end()) {
            FI_HILOGE("faild to find callback");
            ThrowMotionErr(env, UNSUBSCRIBE_EXCEPTION, "Unsubscribe failed");
            return false;
        }
        cb = it->second;
    }
    // 先移除当前 env 的 target（锁外，内部只拿 mutex_）
    cb->RemoveTarget(shared_from_this());
    if (cb->HasTargets()) {
        // 仍有其它 env 在监听：对外表现为“取消成功”，但不触发 service unsubscribe
        return true;
    }

    // 需要成为最后一个 target：尝试从 map 中删除（锁内只做 map 操作）
    {
        std::lock_guard<std::mutex> lk(g_callbacksMutex);
        auto it = g_typeCallbacks.find(type);
        if (it == g_typeCallbacks.end() || it->second != cb) {
            return true; // 其他线程可能已经订阅，视为无需unsubscribe
        }
        // 再确认一次，避免窗口期其它线程 AddTarget
        if (cb->HasTargets()) {
            return true;
        }
        g_typeCallbacks.erase(it);
    }

    // IPC 调用在锁外
    int32_t ret = g_motionClient.UnsubscribeCallback(type, cb);
    if (ret == RET_OK) {
        return true;
    } else if (ret == PERMISSION_DENIED) {
        FI_HILOGE("failed to unsubscribe");
        ThrowMotionErr(env, PERMISSION_EXCEPTION, "Permission denined");
        return false;
    } else if (ret == DEVICE_EXCEPTION || ret == HOLDING_HAND_FEATURE_DISABLE) {
        FI_HILOGE("failed to unsubscribe");
        ThrowMotionErr(env, DEVICE_EXCEPTION, "Device not support");
        return false;
    } else {
        FI_HILOGE("failed to unsubscribe");
        ThrowMotionErr(env, UNSUBSCRIBE_EXCEPTION, "Unsubscribe failed");
        return false;
    }
}

void MotionNapi::UnsubscribeFromServiceNoThrow(int32_t type)
{
    // 只用于析构不throwMotionErr
    sptr<MotionCallback> cb;
    bool needUnsubscribe = false;
    {
        std::lock_guard<std::mutex> lk(g_callbacksMutex);
        auto it = g_typeCallbacks.find(type);
        if (it == g_typeCallbacks.end()) {
            return;
        }
        cb = it->second;
        cb->RemoveTarget(shared_from_this());
        if (!cb->HasTargets()) {
            g_typeCallbacks.erase(it);
            needUnsubscribe = true;
        }
    }

    if (!needUnsubscribe) {
        FI_HILOGE("type no needUnsubscribe");
        return;
    }

    int32_t ret = g_motionClient.UnsubscribeCallback(type, cb);
    if (ret != RET_OK) {
        // 这里仅记录日志，不抛异常
        FI_HILOGE("UnsubscribeCallback failed in finalize, type=%{public}d, ret=%{public}d", type, ret);
    }
}

void MotionNapi::UnsubscribeFromAllTypes()
{
    FI_HILOGD("Enter");
    std::vector<int32_t> types;
    types.reserve(events_.size());
    for (auto &p : events_) {
        types.push_back(p.first);
    }
    for (auto t : types) {
        UnsubscribeFromService(env_, t);
    }
}

void MotionNapi::UnsubscribeFromAllTypesNoThrow()
{
    FI_HILOGD("Enter");
    std::vector<int32_t> types;
    types.reserve(events_.size());
    for (auto &p : events_) {
        types.push_back(p.first);
    }
    for (auto t : types) {
        // 析构专用
        UnsubscribeFromServiceNoThrow(t);
    }
}

void MotionNapi::PostMotionEvent(int32_t type, int32_t status)
{
    // 从 binder/service线程投递回 env对应的JS线程再触发js回调。
    auto selfW = weak_from_this();
    napi_env env = env_;
    auto task = [selfW, type, status]() {
        auto self = selfW.lock();
        if (!self) {
            return;
        }
        MotionEvent ev;
        ev.type = type;
        ev.status = status;
        // 只关心 status；不转发其他
        ev.dataLen = 0;
        ev.data = nullptr;
        self->OnEventOperatingHand(type, 1, ev);
    };
    if (napi_send_event(env, task, napi_eprio_immediate) != napi_ok) {
        FI_HILOGE("Failed to SendEvent");
    }
}

void MotionNapi::InvokeOperatingHandOnce(napi_ref handlerRef, int32_t status)
{
    // 必须在 env_ 对应的 JS 线程执行（由 complete 或 napi_send_event 投递保证）。
    if (env_ == nullptr || handlerRef == nullptr) {
        return;
    }

    napi_value handler = nullptr;
    napi_status ret = napi_get_reference_value(env_, handlerRef, &handler);
    if (ret == napi_ok && handler != nullptr) {
        MotionEvent ev;
        ev.status = status;
        ev.data = nullptr;
        // ConvertOperatingHandData 内部会调用 napi_call_function 等 N-API
        ConvertOperatingHandData(handler, 1, ev);
    } else {
        FI_HILOGE("napi_get_reference_value failed, ret:%{public}d", ret);
    }
    // 一次性 ref：必须释放，避免泄露
    napi_delete_reference(env_, handlerRef);
}

bool MotionNapi::ScheduleOperatingHandOnceDelayed(napi_ref handlerRef, int32_t status, uint32_t delayMs)
{
    // 约束：业务侧不能直接调用 uv_queue_work。
    // 方案：使用 N-API 的 napi_async_work（execute 工作线程延时；complete 回 JS 线程触发回调）。
    if (env_ == nullptr || handlerRef == nullptr) {
        return false;
    }

    struct DelayedOnceCtx {
        napi_env env {nullptr};
        std::weak_ptr<MotionNapi> weak;
        napi_ref handlerRef {nullptr};
        int32_t status {0};
        uint32_t delayMs {0};
        napi_async_work work {nullptr};
    };

    auto *ctx = new (std::nothrow) DelayedOnceCtx;
    if (ctx == nullptr) {
        return false;
    }
    ctx->env = env_;
    ctx->weak = shared_from_this(); // MotionNapi 已继承 enable_shared_from_this
    ctx->handlerRef = handlerRef;
    ctx->status = status;
    ctx->delayMs = delayMs;

    napi_value resourceName = nullptr;
    napi_status sts = napi_create_string_utf8(env_, "MotionDelayedOnce", NAPI_AUTO_LENGTH, &resourceName);
    if (sts != napi_ok) {
        delete ctx;
        return false;
    }

    auto execute = [](napi_env, void *data) {
        auto *ctxdata = static_cast<DelayedOnceCtx *>(data);
        usleep(static_cast<useconds_t>(ctxdata->delayMs) * 1000);
    };

    auto complete = [](napi_env, napi_status, void *data) {
        auto *ctxdata = static_cast<DelayedOnceCtx *>(data);
        auto sp = ctxdata->weak.lock();
        if (sp) {
            // JS 线程：InvokeOperatingHandOnce 内部会释放 handlerRef
            sp->InvokeOperatingHandOnce(ctxdata->handlerRef,  ctxdata->status);
        } else {
            // MotionNapi 已析构：仍需释放引用避免泄露（complete 在 JS 线程，安全）
            if (ctxdata->env != nullptr && ctxdata->handlerRef != nullptr) {
                napi_delete_reference(ctxdata->env, ctxdata->handlerRef);
            }
        }

        if (ctxdata->env != nullptr && ctxdata->work != nullptr) {
            napi_delete_async_work(ctxdata->env, ctxdata->work);
        }
        delete ctxdata;
    };

    sts = napi_create_async_work(env_, nullptr, resourceName, execute, complete, ctx, &ctx->work);
    if (sts != napi_ok || ctx->work == nullptr) {
        delete ctx;
        return false;
    }

    sts = napi_queue_async_work(env_, ctx->work);
    if (sts != napi_ok) {
        napi_delete_async_work(env_, ctx->work);
        delete ctx;
        return false;
    }
    return true;
}
#endif

std::shared_ptr<MotionNapi> MotionNapi::GetOrCreateInstance(napi_env env, napi_value jsThis)
{
    // g_instancesMutex 只保护 g_instances 读写，不在持锁状态下调用 N-API（例如 napi_wrap），
    // 先在锁内快速查询是否已存在
    if (auto exist = TryGetExistingInstanceLocked(env)) {
        return exist;
    }
    // 锁外创建对象（避免在锁内可能的异常/耗时的操作）
    auto sp = std::make_shared<MotionNapi>(env, jsThis);
    // 锁内check + emplace, 避免并发
    {
        std::lock_guard<std::mutex> lk(g_instancesMutex);
        auto it = g_instances.find(env);
        if (it != g_instances.end()) {
            auto exist = it->second.lock();
            if (exist) {
                return exist; // 其他线程已放入
            }
            it->second = sp; // weak已过期 覆盖成新的
        } else {
            g_instances.emplace(env, sp);
        }
    }
    // 锁外做napi_wrap
    // new 一个 holder（nothrow），holder 内持有 shared_ptr
    struct InstanceHolder {
        std::shared_ptr<MotionNapi> sp;
    };
    auto *holder = new (std::nothrow) InstanceHolder{sp};
    if (holder == nullptr) {
        FI_HILOGE("faild to alloc InstanceHolder");
        // 回滚占坑
        RollbackInstancesLocked(env, sp);
        return nullptr;
    }

    napi_status status = napi_wrap(env, jsThis, reinterpret_cast<void *>(holder),
        [](napi_env env, void *data, void *hint) {
            (void)hint;
            auto *holder = reinterpret_cast<InstanceHolder *>(data);
            // 先从实例表中移除
            {
                std::lock_guard<std::mutex> lk(g_instancesMutex);
                g_instances.erase(env);
            }
            // 再清理 exportsRef
            TakeAndDeleteExportsRef(env);
            // 释放holder 触发 MotionNapi 析构
            delete holder;
        }, nullptr, nullptr);
    if (status != napi_ok) {
        FI_HILOGE("napi_wrap failed");
        delete holder; // wrap 失败时立即释放
        // 回滚
        RollbackInstancesLocked(env, sp);
        return nullptr;
    }
    return sp;
}

void MotionNapi::RollbackInstancesLocked(napi_env env, const std::shared_ptr<MotionNapi> &sp)
{
    std::lock_guard<std::mutex> lk(g_instancesMutex);
    auto it = g_instances.find(env);
    if (it == g_instances.end()) {
        return;
    }

    auto current = it->second.lock();
    if (current && current.get() == sp.get()) {
        g_instances.erase(it);
    }
}

std::shared_ptr<MotionNapi> MotionNapi::TryGetExistingInstanceLocked(napi_env env)
{
    std::lock_guard<std::mutex> lk(g_instancesMutex);
    auto it = g_instances.find(env);
    if (it == g_instances.end()) {
        return nullptr;
    }
    return it->second.lock();
}

std::shared_ptr<MotionNapi> MotionNapi::GetInstance(napi_env env)
{
    FI_HILOGD("Enter");
    std::lock_guard<std::mutex> lk(g_instancesMutex);
    auto it = g_instances.find(env);
    if (it == g_instances.end()) {
        return nullptr;
    }
    return it->second.lock();
}

napi_value MotionNapi::SubscribeMotion(napi_env env, napi_callback_info info)
{
    FI_HILOGD("Enter");
#ifdef MOTION_ENABLE
    if (processorId == EVENT_NO_INITIALIZE) {
        processorId = DeviceStatus::NapiEventUtils::AddProcessor();
    }
    int64_t beginTime = DeviceStatus::NapiEventUtils::GetSysClockTime();
    std::string transId = std::string("transId_") + std::to_string(std::rand());
#endif
    size_t argc = ARG_2;
    napi_value args[ARG_2] = { nullptr };
    napi_value jsThis = nullptr;
    napi_value result = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr);
    if (status != napi_ok) {
        ThrowMotionErr(env, SUBSCRIBE_EXCEPTION, "napi_get_cb_info failed");
        return nullptr;
    }

    if (!ValidateArgsType(env, args, argc, EXPECTED_SUB_ARG_TYPES)) {
        ThrowMotionErr(env, PARAM_EXCEPTION, "validateargstype failed");
        return nullptr;
    }

    std::string typeStr;
    if (!TransJsToStr(env, args[ARG_0], typeStr)) {
        ThrowMotionErr(env, SUBSCRIBE_EXCEPTION, "Trans to string failed");
        return nullptr;
    }

    int32_t type = GetMotionType(typeStr);
    if (type == INVALID_MOTION_TYPE) {
        ThrowMotionErr(env, PARAM_EXCEPTION, "Type is illegal");
        return nullptr;
    }

    // 用stable this + GetOrCreateInstance
    napi_value stableThis = GetStableThis(env, jsThis);
    auto motion = GetOrCreateInstance(env, stableThis);
    if (motion == nullptr) {
        ThrowMotionErr(env, SUBSCRIBE_EXCEPTION, "Failed to get g_motionObj");
        return nullptr;
    }

#ifdef MOTION_ENABLE
    bool serviceAlreadySubscribed = false;
    if (!motion->SubscribeToService(env, type, serviceAlreadySubscribed)) {
        return nullptr;
    }

    bool isNewHandler = false;
    if (!motion->AddCallbackEx(type, args[ARG_1], isNewHandler)) {
        ThrowMotionErr(env, SERVICE_EXCEPTION, "AddCallback failed");
        return nullptr;
    }

    // 如果服务已订阅 并且这是此环境的新js function ，则立即使用最新状态回调。
    if (serviceAlreadySubscribed && isNewHandler) {
        MotionEvent latest = g_motionClient.GetMotionData(type);
        // Only invoke the newly-added handler (args[ARG_1]) once.
        int32_t statusVal = latest.status;
        if (statusVal < BASE_HAND) {
            FI_HILOGD("unknown latest status");
            statusVal = HoldPostureStatus::UNKNOWN;
        }
        // 延迟 5ms 再回调一次
        constexpr uint32_t kInitialCbDelayMs = 5;
        napi_ref onceHandlerRef = nullptr;
        napi_status refRet = napi_create_reference(env, args[ARG_1], 1, &onceHandlerRef);
        if (env != motion->env_ || refRet != napi_ok || onceHandlerRef == nullptr) {
            FI_HILOGE("napi_create_reference failed for delayed invoke, ret:%{public}d", refRet);
        } else {
            if (!motion->ScheduleOperatingHandOnceDelayed(onceHandlerRef, statusVal, kInitialCbDelayMs)) {
                // async_work 失败：complete 不会来，所以这里必须释放 ref，避免泄露
                napi_delete_reference(env, onceHandlerRef);
            }
        }
    }

    if (processorId == EVENT_NOT_SUPPORT) {
        FI_HILOGW("Non-applications do not support breakpoint");
    } else {
        std::string apiName = "motion." + typeStr + ".on";
        DeviceStatus::NapiEventUtils::WriteEndEvent(transId, apiName, beginTime, 0, 0);
    }
    napi_get_undefined(env, &result);
    return result;
#else
    ThrowMotionErr(env, DEVICE_EXCEPTION, "Device not support");
    return result;
#endif
}

napi_value MotionNapi::UnSubscribeMotion(napi_env env, napi_callback_info info)
{
    FI_HILOGD("Enter");
#ifdef MOTION_ENABLE
    if (processorId == EVENT_NO_INITIALIZE) {
        processorId = DeviceStatus::NapiEventUtils::AddProcessor();
    }
    int64_t beginTime = DeviceStatus::NapiEventUtils::GetSysClockTime();
    std::string transId = std::string("transId_") + std::to_string(std::rand());
#endif
    auto motion = GetInstance(env);
    if (motion == nullptr) {
        ThrowMotionErr(env, UNSUBSCRIBE_EXCEPTION, "Motion instance not found in this env");
        return nullptr;
    }

    size_t argc = ARG_2;
    napi_value args[ARG_2] = { nullptr };
    napi_value jsThis = nullptr;
    napi_value result = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr);
    if (status != napi_ok) {
        ThrowMotionErr(env, UNSUBSCRIBE_EXCEPTION, "napi_get_cb_info is failed");
        return nullptr;
    }

    auto expectedArgs = EXPECTED_UNSUB_TWO_ARG_TYPES;
    if (argc != ARG_2) {
        expectedArgs = EXPECTED_UNSUB_ONE_ARG_TYPES;
    }
    if (!ValidateArgsType(env, args, argc, expectedArgs)) {
        ThrowMotionErr(env, PARAM_EXCEPTION, "validateargstype failed");
        return nullptr;
    }

    std::string typeStr;
    if (!TransJsToStr(env, args[ARG_0], typeStr)) {
        ThrowMotionErr(env, UNSUBSCRIBE_EXCEPTION, "Trans to string failed");
        return nullptr;
    }

    int32_t type = GetMotionType(typeStr);
    if (type == INVALID_MOTION_TYPE) {
        ThrowMotionErr(env, PARAM_EXCEPTION, "Type is illegal");
        return nullptr;
    }

#ifdef MOTION_ENABLE
    if (argc != ARG_2) {
        if (!motion->RemoveAllCallback(type)) {
            ThrowMotionErr(env, SERVICE_EXCEPTION, "RemoveCallback failed");
            return nullptr;
        }
    } else {
        if (!motion->RemoveCallback(type, args[ARG_1])) {
            ThrowMotionErr(env, SERVICE_EXCEPTION, "RemoveCallback failed");
            return nullptr;
        }
    }
    // 如果仍然有监听器监听此类事件
    if (!motion->CheckEvents(type)) {
        napi_get_undefined(env, &result);
        return result;
    }

    if (!motion->UnsubscribeFromService(env, type)) {
        return nullptr;
    }

    if (processorId == EVENT_NOT_SUPPORT) {
        FI_HILOGW("Non-applications do not support breakpoint");
    } else {
        std::string apiName = "motion." + typeStr + ".off";
        DeviceStatus::NapiEventUtils::WriteEndEvent(transId, apiName, beginTime, 0, 0);
    }
    napi_get_undefined(env, &result);
    return result;
#else
    ThrowMotionErr(env, DEVICE_EXCEPTION, "Device not support");
    return result;
#endif
}

napi_value MotionNapi::GetRecentOptHandStatus(napi_env env, napi_callback_info info)
{
    FI_HILOGD("Enter");
    napi_value result = nullptr;
    size_t argc = ARG_0;
    napi_value jsThis;

    napi_status status = napi_get_cb_info(env, info, &argc, NULL, &jsThis, nullptr);
    if (status != napi_ok) {
        ThrowMotionErr(env, SERVICE_EXCEPTION, "napi_get_cb_info failed");
        return nullptr;
    }

#ifdef MOTION_ENABLE
    MotionEvent motionEvent = g_motionClient.GetMotionData(MOTION_TYPE_OPERATING_HAND);
    if (motionEvent.status == DEVICE_EXCEPTION) {
        ThrowMotionErr(env, DEVICE_EXCEPTION, "Device not support");
        return nullptr;
    }
    if (motionEvent.status == -1) {
        ThrowMotionErr(env, PERMISSION_EXCEPTION, "Invalid Type");
        return nullptr;
    }
#endif
    auto motion = GetOrCreateInstance(env, jsThis);
#ifdef MOTION_ENABLE
    if (motion == nullptr) {
        ThrowMotionErr(env, SERVICE_EXCEPTION, "Error invalid type");
        return nullptr;
    }
    napi_status ret = napi_create_int32(env, static_cast<int32_t>(motionEvent.status), &result);
    if (ret != napi_ok) {
        ThrowMotionErr(env, SERVICE_EXCEPTION, "napi_create_int32 failed");
        return nullptr;
    }
#else
    ThrowMotionErr(env, DEVICE_EXCEPTION, "Device not support");
#endif
    FI_HILOGD("Exit");
    return result;
}

void MotionNapi::SaveExportsWeakRef(napi_env env, napi_value exports)
{
    FI_HILOGD("Enter");
    // 先锁内判断是否已存在
    {
        std::lock_guard<std::mutex> lk(g_exportsMutex);
        auto it = g_exportsRefs.find(env);
        if (it != g_exportsRefs.end() && it->second != nullptr) {
            return;
        }
    }

    // 锁外做 N-API 创建 weak ref
    napi_ref newRef = nullptr;
    napi_status st = napi_create_reference(env, exports, 0, &newRef);
    if (st != napi_ok || newRef == nullptr) {
        FI_HILOGE("SaveExportsWeakRef: napi_create_reference failed");
        return;
    }

    // 再锁内写入
    napi_ref toDelete = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_exportsMutex);
        auto it = g_exportsRefs.find(env);
        if (it != g_exportsRefs.end() && it->second != nullptr) {
            // 已经有人写进去了：我们刚创建的 newRef 需要释放
            toDelete = newRef;
        } else {
            g_exportsRefs[env] = newRef;
            newRef = nullptr;
        }
    }

    // 锁外释放多余ref
    if (toDelete != nullptr) {
        napi_delete_reference(env, toDelete);
    }
}

// 获取稳定的 this：优先用 exports（如果 weak ref 还活着）；否则退回调用时 jsThis
napi_value MotionNapi::GetStableThis(napi_env env, napi_value jsThis)
{
    napi_ref ref = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_exportsMutex);
        auto it = g_exportsRefs.find(env);
        if (it != g_exportsRefs.end()) {
            ref = it->second;
        }
    }

    if (ref != nullptr) {
        napi_value exportsObj = nullptr;
        napi_status st = napi_get_reference_value(env, ref, &exportsObj);
        if (st == napi_ok && exportsObj != nullptr) {
            return exportsObj;
        }
    }
    return jsThis; // 兜底：如果 exports 已 GC 或 ref 不存在，就退回调用 this
}

void MotionNapi::TakeAndDeleteExportsRef(napi_env env)
{
    napi_ref ref = nullptr;
    // 锁内做map删除操作
    {
        std::lock_guard<std::mutex> lk(g_exportsMutex);
        auto it = g_exportsRefs.find(env);
        if (it == g_exportsRefs.end()) {
            return;
        }
        ref = it->second;
        g_exportsRefs.erase(it);
    }
    // 锁外做 napi_delete_reference
    if (ref != nullptr) {
        napi_delete_reference(env, ref);
    }
}

napi_value MotionNapi::Init(napi_env env, napi_value exports)
{
    FI_HILOGD("Enter");
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_FUNCTION("on", SubscribeMotion),
        DECLARE_NAPI_STATIC_FUNCTION("off", UnSubscribeMotion),
        DECLARE_NAPI_STATIC_FUNCTION("getRecentOperatingHandStatus", GetRecentOptHandStatus),
    };
    MSDP_CALL(napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    // 保存 exports weak ref（后续用它作为稳定 this）
    SaveExportsWeakRef(env, exports);

    napi_value operatingHandStatus;
    napi_status status = napi_create_object(env, &operatingHandStatus);
    if (status != napi_ok) {
        FI_HILOGE("Failed create object");
        return exports;
    }

    SetInt32Property(env, operatingHandStatus, BASE_HAND, "UNKNOWN_STATUS");
    SetInt32Property(env, operatingHandStatus, LEFT_HAND, "LEFT_HAND_OPERATED");
    SetInt32Property(env, operatingHandStatus, RIGHT_HAND, "RIGHT_HAND_OPERATED");
    SetPropertyName(env, exports, "OperatingHandStatus", operatingHandStatus);
    DefineHoldingHandStatus(env, exports);
    FI_HILOGD("Exit");
    return exports;
}

void MotionNapi::DefineHoldingHandStatus(napi_env env, napi_value exports)
{
    napi_value holdingHandStatus;
    napi_status status = napi_create_object(env, &holdingHandStatus);
    if (status != napi_ok) {
        FI_HILOGE("Failed create object");
        return;
    }

    SetInt32Property(env, holdingHandStatus, HoldPostureStatus::UNKNOWN, "UNKNOWN_STATUS");
    SetInt32Property(env, holdingHandStatus, HoldPostureStatus::NOT_HELD, "NOT_HELD");
    SetInt32Property(env, holdingHandStatus, HoldPostureStatus::LEFT_HAND_HELD, "LEFT_HAND_HELD");
    SetInt32Property(env, holdingHandStatus, HoldPostureStatus::RIGHT_HAND_HELD, "RIGHT_HAND_HELD");
    SetInt32Property(env, holdingHandStatus, HoldPostureStatus::BOTH_HAND_HELD, "BOTH_HANDS_HELD");
    SetPropertyName(env, exports, "HoldingHandStatus", holdingHandStatus);
}

void MotionNapi::SetInt32Property(napi_env env, napi_value targetObj, int32_t value, const char *propName)
{
    napi_value prop = nullptr;
    napi_status ret = napi_create_int32(env, value, &prop);
    if (ret != napi_ok) {
        FI_HILOGE("napi_create_int32 failed");
        return;
    }
    SetPropertyName(env, targetObj, propName, prop);
}

void MotionNapi::SetPropertyName(napi_env env, napi_value targetObj, const char *propName, napi_value propValue)
{
    napi_status status = napi_set_named_property(env, targetObj, propName, propValue);
    if (status != napi_ok) {
        FI_HILOGE("Failed to set the name property");
        return;
    }
}

bool MotionNapi::ValidateArgsType(napi_env env, napi_value *args, size_t argc,
    const std::vector<std::string> &expectedTypes)
{
    FI_HILOGD("Enter");
    napi_status status = napi_ok;
    napi_valuetype valueType = napi_undefined;

    if (argc != expectedTypes.size()) {
        FI_HILOGE("Wrong number of arguments");
        return false;
    }

    for (size_t i = 0; i < argc; ++i) {
        status = napi_typeof(env, args[i], &valueType);
        if (status != napi_ok) {
            FI_HILOGE("Error while checking arguments types");
            return false;
        }
        std::string expectedType = expectedTypes[i];
        if ((expectedType == "string" && valueType != napi_string) ||
            (expectedType == "function" && valueType != napi_function)) {
                FI_HILOGE("Wrong argument type");
                return false;
        }
    }
    return true;
}

bool MotionNapi::TransJsToStr(napi_env env, napi_value value, std::string &str)
{
    FI_HILOGD("Enter");
    size_t strlen = 0;
    napi_status status = napi_get_value_string_utf8(env, value, nullptr, 0, &strlen);
    if (status != napi_ok) {
        FI_HILOGE("Error string length invalid");
        return false;
    }
    if (strlen < 0 || strlen > MAX_ARG_STRING_LEN) {
        FI_HILOGE("The string length invalid");
        return false;
    }
    std::vector<char> buf(strlen + 1);
    status = napi_get_value_string_utf8(env, value, buf.data(), strlen+1, &strlen);
    if (status != napi_ok) {
        FI_HILOGE("napi_get_value_string_utf8 failed");
        return false;
    }
    str = buf.data();
    return true;
}

EXTERN_C_START
/*
 * function for module exports
 */
static napi_value MotionInit(napi_env env, napi_value exports)
{
    FI_HILOGD("Enter");
    napi_value ret = MotionNapi::Init(env, exports);
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
    .nm_filename = "multimodalAwareness.motion",
    .nm_register_func = MotionInit,
    .nm_modname = "multimodalAwareness.motion",
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
} // namespace Msdp
} // namespace OHOS
