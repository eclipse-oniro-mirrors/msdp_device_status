/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "drop_event_napi.h"

#include <map>
#include <string>

#include "devicestatus_define.h"
#include "device_status_napi_error.h"
#include "fi_log.h"
#include "parameters.h"
#ifdef MOTION_ENABLE
#include <algorithm>
#include <new>
#include <unordered_map>

#include "motion_client.h"
#endif // MOTION_ENABLE

#undef LOG_TAG
#define LOG_TAG "DeviceStatusMotionEventNapi"

namespace OHOS {
namespace Msdp {
namespace {
constexpr uint8_t ARG_0 = 0;
constexpr uint8_t ARG_1 = 1;

void ThrowDropDetectionError(napi_env env, int32_t code, const std::string &message)
{
    if (code != DeviceStatusV1::DEVICE_EXCEPTION && code != DeviceStatusV1::PARAM_EXCEPTION) {
        DeviceStatusV1::ThrowDeviceStatusErr(env, code, message);
        return;
    }
    FI_HILOGE("printMsg:%{public}s, errCode:%{public}d", message.c_str(), code);
    const std::string errorMessage = (code == DeviceStatusV1::DEVICE_EXCEPTION ?
        DropDetectionError::NOT_SUPPORTED : DropDetectionError::PARAMETER_PREFIX + message);
    napi_value error = DeviceStatusV1::CreateDeviceStatusNapiError(env, code, errorMessage);
    napi_throw(env, error);
}

const char *GetNapiTypeName(napi_valuetype type)
{
    static const std::map<napi_valuetype, const char *> typeNames = {
        { napi_undefined, "undefined" },
        { napi_null, "null" },
        { napi_boolean, "boolean" },
        { napi_number, "number" },
        { napi_string, "string" },
        { napi_symbol, "symbol" },
        { napi_object, "object" },
        { napi_external, "external" },
        { napi_bigint, "bigint" },
    };
    auto iter = typeNames.find(type);
    return iter != typeNames.end() ? iter->second : "unknown";
}

bool CheckDeviceTypeForDropDetection()
{
    std::string deviceType = OHOS::system::GetParameter("const.product.devicetype", "");
    FI_HILOGD("deviceType:%{public}s", deviceType.c_str());
    return deviceType == "phone";
}

#ifdef MOTION_ENABLE
constexpr int32_t MOTION_OPERATION_FAILED = -2;
constexpr int32_t MOTION_SUBSCRIBE_EXCEPTION = 31500002;
constexpr int32_t MOTION_UNSUBSCRIBE_EXCEPTION = 31500003;
auto &g_motionClient = MotionClient::GetInstance();
std::mutex g_instancesMutex;
std::unordered_map<napi_env, std::shared_ptr<DeviceStatusMotionEventNapi>> g_instances;
// Only subscription operations take this lock; native event delivery does not.
std::mutex g_subscriptionMutex;
// Serialize registration changes with recipient snapshots across all environments.
// Never hold this lock while invoking application callbacks or native subscription IPC.
std::mutex g_callbacksMutex;
sptr<DropDetectCallback> g_dropCallback;

int32_t ConvertMotionErrorCode(int32_t ret, int32_t operationErrCode)
{
    if (ret == DeviceStatusV1::DEVICE_EXCEPTION) {
        return DeviceStatusV1::DEVICE_EXCEPTION;
    }
    if (operationErrCode == DeviceStatusV1::SUBSCRIBE_EXCEPTION &&
        (ret == MOTION_OPERATION_FAILED || ret == MOTION_SUBSCRIBE_EXCEPTION ||
        ret == DeviceStatusV1::SUBSCRIBE_EXCEPTION)) {
        return DeviceStatusV1::SUBSCRIBE_EXCEPTION;
    }
    if (operationErrCode == DeviceStatusV1::UNSUBSCRIBE_EXCEPTION &&
        (ret == MOTION_OPERATION_FAILED || ret == MOTION_UNSUBSCRIBE_EXCEPTION ||
        ret == DeviceStatusV1::UNSUBSCRIBE_EXCEPTION)) {
        return DeviceStatusV1::UNSUBSCRIBE_EXCEPTION;
    }
    return DeviceStatusV1::SERVICE_EXCEPTION;
}

void ThrowMotionError(napi_env env, int32_t ret, int32_t operationErrCode, const char *message)
{
    int32_t code = ConvertMotionErrorCode(ret, operationErrCode);
    ThrowDropDetectionError(env, code, message);
}

#endif // MOTION_ENABLE
} // namespace

// JS API entry points.
napi_value DeviceStatusMotionEventNapi::OnDropDetect(napi_env env, napi_callback_info info)
{
    FI_HILOGD("Enter");
    if (!CheckDeviceTypeForDropDetection()) {
        ThrowDropDetectionError(env, DeviceStatusV1::DEVICE_EXCEPTION, "Device not support");
        return nullptr;
    }
    size_t argc = ARG_0;
    napi_value callback = nullptr;
    napi_value result = nullptr;
    if (!ValidateDropDetectArgs(env, info, true, argc, callback)) {
        return nullptr;
    }
#ifdef MOTION_ENABLE
    auto instance = GetOrCreateInstance(env);
    if (instance == nullptr) {
        ThrowDropDetectionError(env, DeviceStatusV1::SERVICE_EXCEPTION,
            "Failed to get DeviceStatusMotionEventNapi instance");
        return nullptr;
    }
    int32_t addRet = instance->AddCallbackEx(callback);
    if (addRet != RET_OK) {
        ThrowDropDetectionError(env, addRet, "AddCallback failed");
        return nullptr;
    }
    int32_t subscribeRet = instance->SubscribeToService();
    if (subscribeRet != RET_OK) {
        // Remove this registration before throwing, so queued events skip it and
        // rollback NAPI calls run without a pending subscription exception.
        if (instance->RemoveCallback(callback) != RET_OK) {
            FI_HILOGE("Failed to roll back callback after subscription failed");
        }
        ThrowDropDetectionError(env, subscribeRet, "Subscribe failed");
        return nullptr;
    }
    napi_get_undefined(env, &result);
    return result;
#else
    ThrowDropDetectionError(env, DeviceStatusV1::DEVICE_EXCEPTION, "Device not support");
    return result;
#endif // MOTION_ENABLE
}

napi_value DeviceStatusMotionEventNapi::OffDropDetect(napi_env env, napi_callback_info info)
{
    FI_HILOGD("Enter");
    if (!CheckDeviceTypeForDropDetection()) {
        ThrowDropDetectionError(env, DeviceStatusV1::DEVICE_EXCEPTION, "Device not support");
        return nullptr;
    }
    size_t argc = ARG_0;
    napi_value callback = nullptr;
    napi_value result = nullptr;
    if (!ValidateDropDetectArgs(env, info, false, argc, callback)) {
        return nullptr;
    }
#ifdef MOTION_ENABLE
    auto instance = GetInstance(env);
    if (instance == nullptr) {
        ThrowDropDetectionError(env, DeviceStatusV1::UNSUBSCRIBE_EXCEPTION,
            "DeviceStatusMotionEventNapi instance is nullptr");
        return nullptr;
    }
    int32_t removeRet = (argc == ARG_0 ? instance->RemoveAllCallback() :
        instance->RemoveCallback(callback));
    if (removeRet != RET_OK) {
        ThrowDropDetectionError(env, removeRet, "RemoveCallback failed");
        return nullptr;
    }
    if (!instance->HasCallbacks()) {
        int32_t ret = instance->UnsubscribeFromService();
        if (ret != RET_OK) {
            FI_HILOGE("UnsubscribeCallback failed, ret:%{public}d", ret);
            ThrowMotionError(env, ret, DeviceStatusV1::UNSUBSCRIBE_EXCEPTION, "Unsubscribe failed");
            return nullptr;
        }
    }
    napi_get_undefined(env, &result);
    return result;
#else
    ThrowDropDetectionError(env, DeviceStatusV1::DEVICE_EXCEPTION, "Device not support");
    return result;
#endif // MOTION_ENABLE
}

void DeviceStatusMotionEventNapi::DefineDropDetectionStatus(napi_env env, napi_value exports)
{
    napi_value dropDetectionStatus = nullptr;
    napi_status status = napi_create_object(env, &dropDetectionStatus);
    if (status != napi_ok) {
        FI_HILOGE("Failed to create DropDetectionStatus");
        return;
    }
    SetInt32Property(env, dropDetectionStatus,
        static_cast<int32_t>(DropDetectionStatus::STATUS_NORMAL), "STATUS_NORMAL");
    SetInt32Property(env, dropDetectionStatus,
        static_cast<int32_t>(DropDetectionStatus::STATUS_DROPPED), "STATUS_DROPPED");
    SetPropertyName(env, exports, "DropDetectionStatus", dropDetectionStatus);
}

#ifdef MOTION_ENABLE
// Native callback targets.
void DropDetectCallback::OnMotionChanged(const MotionEvent &event)
{
    FI_HILOGD("Enter");
    std::lock_guard<std::mutex> callbackLock(g_callbacksMutex);
    std::vector<std::shared_ptr<DeviceStatusMotionEventNapi>> snapshot;
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

    // AddTarget already prevents duplicate environments.
    for (auto &tmp : snapshot) {
        tmp->PostMotionEvent(event);
    }
    FI_HILOGD("Exit");
}

void DropDetectCallback::AddTarget(const std::shared_ptr<DeviceStatusMotionEventNapi> &target)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = std::remove_if(targets_.begin(), targets_.end(), [](const auto &item) {
        return item.expired();
    });
    targets_.erase(iter, targets_.end());
    for (const auto &item : targets_) {
        if (item.lock() == target) {
            return;
        }
    }
    targets_.push_back(target);
}

void DropDetectCallback::RemoveTarget(const std::shared_ptr<DeviceStatusMotionEventNapi> &target)
{
    FI_HILOGD("Enter");
    if (!target) {
        FI_HILOGE("target is null");
        return;
    }
    std::lock_guard<std::mutex> lk(mutex_);
    targets_.erase(std::remove_if(targets_.begin(), targets_.end(),
        [&target](const std::weak_ptr<DeviceStatusMotionEventNapi>& it) {
            auto sp = it.lock();
            return !sp || sp.get() == target.get();
        }), targets_.end());
}

bool DropDetectCallback::HasTargets() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return std::any_of(targets_.begin(), targets_.end(), [](const auto &item) {
        return !item.expired();
    });
}

// Instance lifecycle.
std::shared_ptr<DeviceStatusMotionEventNapi> DeviceStatusMotionEventNapi::GetInstance(napi_env env)
{
    std::lock_guard<std::mutex> lock(g_instancesMutex);
    auto iter = g_instances.find(env);
    return iter == g_instances.end() ? nullptr : iter->second;
}

std::shared_ptr<DeviceStatusMotionEventNapi> DeviceStatusMotionEventNapi::GetOrCreateInstance(napi_env env)
{
    if (auto instance = GetInstance(env)) {
        return instance;
    }
    auto instance = std::make_shared<DeviceStatusMotionEventNapi>(env);
    // Existing deviceStatus APIs may wrap exports; use environment cleanup to avoid a second wrap.
    if (napi_add_env_cleanup_hook(env, CleanupInstance, env) != napi_ok) {
        FI_HILOGE("napi_add_env_cleanup_hook failed");
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(g_instancesMutex);
    g_instances.emplace(env, instance);
    return instance;
}

void DeviceStatusMotionEventNapi::CleanupInstance(void *data)
{
    auto env = static_cast<napi_env>(data);
    std::shared_ptr<DeviceStatusMotionEventNapi> instance;
    {
        std::lock_guard<std::mutex> lock(g_instancesMutex);
        auto iter = g_instances.find(env);
        if (iter == g_instances.end()) {
            return;
        }
        instance = iter->second;
        g_instances.erase(iter);
    }
    {
        std::lock_guard<std::mutex> lock(instance->envMutex_);
        instance->env_ = nullptr;
    }
    int32_t ret = instance->UnsubscribeFromService();
    if (ret != RET_OK) {
        FI_HILOGE("UnsubscribeCallback failed in cleanup, ret:%{public}d", ret);
    }
    instance->CleanupDropCallbacks(env);
}

// Service subscriptions.
int32_t DeviceStatusMotionEventNapi::SubscribeToService()
{
    FI_HILOGD("Enter");
    std::lock_guard<std::mutex> lock(g_subscriptionMutex);
    if (g_dropCallback != nullptr) {
        g_dropCallback->AddTarget(shared_from_this());
        return RET_OK;
    }
    sptr<DropDetectCallback> cb = new (std::nothrow) DropDetectCallback();
    if (cb == nullptr) {
        FI_HILOGE("Failed to create DropDetectCallback");
        return DeviceStatusV1::SERVICE_EXCEPTION;
    }
    cb->AddTarget(shared_from_this());
    int32_t ret = g_motionClient.SubscribeCallback(MOTION_TYPE_DROP_DETECTION, cb);
    if (ret != RET_OK) {
        cb->RemoveTarget(shared_from_this());
        FI_HILOGE("SubscribeCallback failed, ret:%{public}d", ret);
        return ConvertMotionErrorCode(ret, DeviceStatusV1::SUBSCRIBE_EXCEPTION);
    }
    g_dropCallback = cb;
    return RET_OK;
}

int32_t DeviceStatusMotionEventNapi::UnsubscribeFromService()
{
    FI_HILOGD("Enter");
    std::lock_guard<std::mutex> lock(g_subscriptionMutex);
    if (g_dropCallback == nullptr) {
        return RET_OK;
    }
    g_dropCallback->RemoveTarget(shared_from_this());
    if (g_dropCallback->HasTargets()) {
        return RET_OK;
    }
    int32_t ret = g_motionClient.UnsubscribeCallback(MOTION_TYPE_DROP_DETECTION, g_dropCallback);
    if (ret == RET_OK) {
        g_dropCallback = nullptr;
    }
    return ret;
}

// Event delivery.
void DeviceStatusMotionEventNapi::PostMotionEvent(const MotionEvent &event)
{
    std::lock_guard<std::mutex> lock(envMutex_);
    if (env_ == nullptr) {
        return;
    }
    auto selfW = weak_from_this();
    int32_t status = event.status;
    CallbackSnapshot callbacks(callbackRefs_.begin(), callbackRefs_.end());
    if (callbacks.empty()) {
        return;
    }
    auto task = [selfW, status, callbacks = std::move(callbacks)]() {
        auto self = selfW.lock();
        if (self == nullptr || self->env_ == nullptr) {
            return;
        }
        self->OnEventDropDetection(status, callbacks);
    };
    if (napi_send_event(env_, task, napi_eprio_immediate, "deviceStatus.dropDetect") != napi_ok) {
        FI_HILOGE("Failed to SendEvent");
    }
}

void DeviceStatusMotionEventNapi::OnEventDropDetection(int32_t status, const CallbackSnapshot &callbacks)
{
    for (const auto &callback : callbacks) {
        napi_value handler = nullptr;
        {
            std::lock_guard<std::mutex> lock(g_callbacksMutex);
            // Function equality is insufficient: off(f) followed by on(f) is a new
            // registration, even if the runtime reuses the same napi_ref address.
            if (callbackRefs_.find(callback) == callbackRefs_.end()) {
                continue;
            }
            if (napi_get_reference_value(env_, callback->handlerRef, &handler) != napi_ok) {
                FI_HILOGE("napi_get_reference_value failed");
                continue;
            }
        }
        // The napi_send_event handle scope keeps the function alive during reentry.
        if (!ConvertDropDetectionData(handler, status)) {
            FI_HILOGE("Failed to dispatch drop event");
            continue;
        }
    }
}

bool DeviceStatusMotionEventNapi::ConvertDropDetectionData(napi_value handler, int32_t status)
{
    int32_t dropStatus = static_cast<int32_t>(status == 0 || status == -1 ?
        DropDetectionStatus::STATUS_NORMAL : DropDetectionStatus::STATUS_DROPPED);
    napi_value result = nullptr;
    if (napi_create_int32(env_, dropStatus, &result) != napi_ok) {
        FI_HILOGE("napi_create_int32 failed");
        return false;
    }
    napi_value callResult = nullptr;
    napi_status ret = napi_call_function(env_, nullptr, handler, 1, &result, &callResult);
    if (ret != napi_ok) {
        FI_HILOGE("napi_call_function ret %{public}d", ret);
        return false;
    }
    return true;
}

// JS callback management.
int32_t DeviceStatusMotionEventNapi::AddCallbackEx(napi_value handler)
{
    std::lock_guard<std::mutex> lock(g_callbacksMutex);
    for (const auto &callback : callbackRefs_) {
        napi_value onHandler = nullptr;
        if (napi_get_reference_value(env_, callback->handlerRef, &onHandler) != napi_ok) {
            FI_HILOGE("napi_get_reference_value failed");
            return DeviceStatusV1::SERVICE_EXCEPTION;
        }
        if (IsSameValue(env_, handler, onHandler)) {
            return DeviceStatusV1::SUBSCRIBE_EXCEPTION;
        }
    }
    napi_ref onHandlerRef = nullptr;
    if (napi_create_reference(env_, handler, 1, &onHandlerRef) != napi_ok || onHandlerRef == nullptr) {
        FI_HILOGE("napi_create_reference failed");
        if (onHandlerRef != nullptr) {
            napi_delete_reference(env_, onHandlerRef);
        }
        return DeviceStatusV1::SERVICE_EXCEPTION;
    }
    if (!callbackRefs_.insert(std::make_shared<CallbackRegistration>(onHandlerRef)).second) {
        FI_HILOGE("Failed to insert ref");
        napi_delete_reference(env_, onHandlerRef);
        return DeviceStatusV1::SERVICE_EXCEPTION;
    }
    return RET_OK;
}

int32_t DeviceStatusMotionEventNapi::RemoveCallback(napi_value handler)
{
    std::lock_guard<std::mutex> lock(g_callbacksMutex);
    if (callbackRefs_.empty()) {
        FI_HILOGE("No drop callbacks");
        return DeviceStatusV1::UNSUBSCRIBE_EXCEPTION;
    }
    for (auto it = callbackRefs_.begin(); it != callbackRefs_.end(); ++it) {
        napi_value onHandler = nullptr;
        if (napi_get_reference_value(env_, (*it)->handlerRef, &onHandler) != napi_ok) {
            FI_HILOGE("napi_get_reference_value failed");
            return DeviceStatusV1::SERVICE_EXCEPTION;
        }
        if (IsSameValue(env_, handler, onHandler)) {
            if (napi_delete_reference(env_, (*it)->handlerRef) != napi_ok) {
                FI_HILOGE("napi_delete_reference failed");
                return DeviceStatusV1::SERVICE_EXCEPTION;
            }
            callbackRefs_.erase(it);
            return RET_OK;
        }
    }
    return DeviceStatusV1::UNSUBSCRIBE_EXCEPTION;
}

int32_t DeviceStatusMotionEventNapi::RemoveAllCallback()
{
    std::lock_guard<std::mutex> lock(g_callbacksMutex);
    if (callbackRefs_.empty()) {
        FI_HILOGE("No drop callbacks");
        return DeviceStatusV1::UNSUBSCRIBE_EXCEPTION;
    }
    bool removedAll = true;
    for (auto it = callbackRefs_.begin(); it != callbackRefs_.end();) {
        if (napi_delete_reference(env_, (*it)->handlerRef) != napi_ok) {
            FI_HILOGE("napi_delete_reference failed");
            removedAll = false;
            ++it;
        } else {
            it = callbackRefs_.erase(it);
        }
    }
    return removedAll ? RET_OK : DeviceStatusV1::SERVICE_EXCEPTION;
}

bool DeviceStatusMotionEventNapi::HasCallbacks()
{
    std::lock_guard<std::mutex> lock(g_callbacksMutex);
    return !callbackRefs_.empty();
}

void DeviceStatusMotionEventNapi::CleanupDropCallbacks(napi_env env)
{
    std::lock_guard<std::mutex> lock(g_callbacksMutex);
    for (const auto &callback : callbackRefs_) {
        if (napi_delete_reference(env, callback->handlerRef) != napi_ok) {
            FI_HILOGE("napi_delete_reference failed");
        }
    }
    callbackRefs_.clear();
}

bool DeviceStatusMotionEventNapi::IsSameValue(const napi_env &env, const napi_value &lhs, const napi_value &rhs)
{
    bool result = false;
    if (napi_strict_equals(env, lhs, rhs, &result) != napi_ok) {
        FI_HILOGE("napi_strict_equals failed");
        return false;
    }
    return result;
}
#endif // MOTION_ENABLE

// NAPI helpers.
bool DeviceStatusMotionEventNapi::ValidateDropDetectArgs(napi_env env, napi_callback_info info,
    bool callbackRequired, size_t &argc, napi_value &callback)
{
    FI_HILOGD("Enter");
    argc = ARG_1;
    if (napi_get_cb_info(env, info, &argc, &callback, nullptr, nullptr) != napi_ok) {
        FI_HILOGE("napi_get_cb_info failed");
        ThrowDropDetectionError(env, DeviceStatusV1::SERVICE_EXCEPTION, "napi_get_cb_info failed");
        return false;
    }
    if (argc > ARG_1 || (callbackRequired && argc != ARG_1)) {
        const std::string expectedCount = callbackRequired ? "1" : "0 or 1";
        FI_HILOGE("Incorrect parameter count. Expected: %{public}s, Actual: %{public}zu",
            expectedCount.c_str(), argc);
        ThrowDropDetectionError(env, DeviceStatusV1::PARAM_EXCEPTION,
            DropDetectionError::ParameterCount(expectedCount, argc));
        return false;
    }
    if (argc == ARG_0) {
        return true;
    }
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, callback, &valueType) != napi_ok) {
        FI_HILOGE("Error while checking argument type");
        ThrowDropDetectionError(env, DeviceStatusV1::SERVICE_EXCEPTION, "napi_typeof failed");
        return false;
    }
    if (callbackRequired && (valueType == napi_null || valueType == napi_undefined)) {
        FI_HILOGE("Callback is null or undefined");
        ThrowDropDetectionError(env, DeviceStatusV1::PARAM_EXCEPTION,
            DropDetectionError::CALLBACK_REQUIRED);
        return false;
    }
    if (valueType != napi_function) {
        const char *actualType = GetNapiTypeName(valueType);
        FI_HILOGE("Callback type mismatch, expected:function, actual: %{public}s", actualType);
        ThrowDropDetectionError(env, DeviceStatusV1::PARAM_EXCEPTION,
            DropDetectionError::CallbackType("function", actualType));
        return false;
    }
    return true;
}

void DeviceStatusMotionEventNapi::SetInt32Property(napi_env env, napi_value targetObj, int32_t value,
    const char *propName)
{
    napi_value prop = nullptr;
    napi_status ret = napi_create_int32(env, value, &prop);
    if (ret != napi_ok) {
        FI_HILOGE("napi_create_int32 failed");
        return;
    }
    SetPropertyName(env, targetObj, propName, prop);
}

void DeviceStatusMotionEventNapi::SetPropertyName(napi_env env, napi_value targetObj, const char *propName,
    napi_value propValue)
{
    napi_status status = napi_set_named_property(env, targetObj, propName, propValue);
    if (status != napi_ok) {
        FI_HILOGE("Failed to set the name property");
    }
}

} // namespace Msdp
} // namespace OHOS
