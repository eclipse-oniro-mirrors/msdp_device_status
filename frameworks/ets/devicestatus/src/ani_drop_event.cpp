/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ani_drop_event.h"

#include <algorithm>

#ifdef MOTION_ENABLE
#include "motion_client.h"
#endif // MOTION_ENABLE
#include "ani_error_utils.h"
#include "devicestatus_define.h"
#include "fi_log.h"
#include "taihe/runtime.hpp"

#undef LOG_TAG
#define LOG_TAG "DeviceStatusAniMotionEvent"

namespace OHOS {
namespace Msdp {
namespace DeviceStatusV1 {
#ifdef MOTION_ENABLE
namespace {
constexpr int32_t MOTION_OPERATION_FAILED = -2;
constexpr int32_t MOTION_SUBSCRIBE_EXCEPTION = 31500002;
constexpr int32_t MOTION_UNSUBSCRIBE_EXCEPTION = 31500003;
auto &g_motionClient = MotionClient::GetInstance();

int32_t ConvertMotionErrorCode(int32_t ret, int32_t operationErrCode)
{
    if (ret == DEVICE_EXCEPTION) {
        return DEVICE_EXCEPTION;
    }
    if (operationErrCode == SUBSCRIBE_EXCEPTION &&
        (ret == MOTION_OPERATION_FAILED || ret == MOTION_SUBSCRIBE_EXCEPTION || ret == SUBSCRIBE_EXCEPTION)) {
        return SUBSCRIBE_EXCEPTION;
    }
    if (operationErrCode == UNSUBSCRIBE_EXCEPTION &&
        (ret == MOTION_OPERATION_FAILED || ret == MOTION_UNSUBSCRIBE_EXCEPTION || ret == UNSUBSCRIBE_EXCEPTION)) {
        return UNSUBSCRIBE_EXCEPTION;
    }
    return SERVICE_EXCEPTION;
}
} // namespace

void AniMotionCallback::OnMotionChanged(const MotionEvent &event)
{
    FI_HILOGD("Enter");
    auto data = std::make_shared<MotionEvent>();
    data->type = event.type;
    data->status = event.status;
    EmitOnEvent(data);
    FI_HILOGD("Exit");
}

void AniMotionCallback::EmitOnEvent(std::shared_ptr<MotionEvent> data)
{
    if (data == nullptr) {
        FI_HILOGE("data is nullptr");
        return;
    }
    AniMotionEvent::GetInstance()->OnEventDropDetection(data->type, data);
}
#endif // MOTION_ENABLE

std::shared_ptr<AniMotionEvent> AniMotionEvent::GetInstance()
{
    static std::once_flag flag;
    static std::shared_ptr<AniMotionEvent> instance_;
    std::call_once(flag, []() {
        instance_ = std::make_shared<AniMotionEvent>();
    });
    return instance_;
}

#ifdef MOTION_ENABLE
bool AniMotionEvent::CheckEvents(int32_t eventType)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = events_.find(eventType);
    return iter == events_.end() || iter->second.empty();
}

int32_t AniMotionEvent::SubscribeCallback(int32_t type, ::taihe::callback_view<void(DropDetectionStatus_t)> f)
{
    auto runner = AppExecFwk::EventRunner::Current();
    if (runner == nullptr) {
        runner = AppExecFwk::EventRunner::GetMainEventRunner();
    }
    if (runner == nullptr) {
        FI_HILOGE("Get event runner failed");
        return SERVICE_EXCEPTION;
    }
    DropDetectCallback callback = f;
    auto record = std::make_shared<DropCallbackInfo>(callback, std::make_shared<AppExecFwk::EventHandler>(runner));
    std::lock_guard<std::mutex> operationLock(subscriptionMutex_);
    int32_t ret = AddCallback(type, record);
    if (ret != RET_OK) {
        return ret;
    }
    if (callbacks_.find(type) != callbacks_.end()) {
        return RET_OK;
    }
    sptr<IMotionCallback> nativeCallback = new (std::nothrow) AniMotionCallback();
    if (nativeCallback == nullptr) {
        RemoveCallback(type, &callback);
        return SERVICE_EXCEPTION;
    }
    ret = g_motionClient.SubscribeCallback(type, nativeCallback);
    if (ret == RET_OK) {
        callbacks_.emplace(type, nativeCallback);
        return RET_OK;
    }
    // Roll back only this registration, including any event tasks queued by the IPC.
    RemoveCallback(type, &callback);
    FI_HILOGE("failed to subscribe, ret:%{public}d", ret);
    return ConvertMotionErrorCode(ret, SUBSCRIBE_EXCEPTION);
}

int32_t AniMotionEvent::UnSubscribeCallback(int32_t type, const DropDetectCallback *callback)
{
    std::lock_guard<std::mutex> operationLock(subscriptionMutex_);
    int32_t ret = RemoveCallback(type, callback);
    if (ret != RET_OK) {
        return ret;
    }
    if (!CheckEvents(type)) {
        return RET_OK;
    }
    auto iter = callbacks_.find(type);
    if (iter == callbacks_.end()) {
        return UNSUBSCRIBE_EXCEPTION;
    }
    ret = g_motionClient.UnsubscribeCallback(type, iter->second);
    if (ret == RET_OK) {
        callbacks_.erase(iter);
        return RET_OK;
    }
    FI_HILOGE("failed to unsubscribe, ret:%{public}d", ret);
    return ConvertMotionErrorCode(ret, UNSUBSCRIBE_EXCEPTION);
}

int32_t AniMotionEvent::AddCallback(int32_t eventType, const std::shared_ptr<DropCallbackInfo> &callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto &records = events_[eventType];
    for (const auto &record : records) {
        if (record->callback == callback->callback) {
            FI_HILOGW("Drop callback already registered, eventType:%{public}d", eventType);
            return SUBSCRIBE_EXCEPTION;
        }
    }
    records.push_back(callback);
    return RET_OK;
}

int32_t AniMotionEvent::RemoveCallback(int32_t eventType, const DropDetectCallback *callback)
{
    // Keep removed Taihe references alive until the collection lock has been released.
    std::vector<std::shared_ptr<DropCallbackInfo>> removed;
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = events_.find(eventType);
    if (iter == events_.end()) {
        return UNSUBSCRIBE_EXCEPTION;
    }
    auto &records = iter->second;
    auto end = std::remove_if(records.begin(), records.end(), [&removed, callback](const auto &record) {
        if (callback != nullptr && !(record->callback == *callback)) {
            return false;
        }
        record->active.store(false);
        removed.push_back(record);
        return true;
    });
    records.erase(end, records.end());
    if (records.empty()) {
        events_.erase(iter);
    }
    return removed.empty() ? UNSUBSCRIBE_EXCEPTION : RET_OK;
}

void AniMotionEvent::OnEventDropDetection(int32_t eventType, const std::shared_ptr<MotionEvent> &event)
{
    if (event == nullptr) {
        FI_HILOGE("Drop event is null, eventType:%{public}d", eventType);
        return;
    }
    FI_HILOGD("eventType: %{public}d,%{public}d", eventType, event->status);
    std::vector<std::shared_ptr<DropCallbackInfo>> records;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto iter = events_.find(eventType);
        if (iter == events_.end()) {
            return;
        }
        records = iter->second;
    }
    DropDetectionStatus_t status = event->status == 0 || event->status == -1 ?
        DropDetectionStatus_t::key_t::STATUS_NORMAL : DropDetectionStatus_t::key_t::STATUS_DROPPED;
    for (const auto &record : records) {
        // Always enqueue: native IPC may synchronously deliver an event while on/off holds
        // subscriptionMutex_. Application callbacks must not run on that IPC stack.
        // A queued task must not keep a cancelled callback (or its event runner) alive.
        auto task = [weakRecord = std::weak_ptr<DropCallbackInfo>(record), status]() {
            auto callbackInfo = weakRecord.lock();
            if (callbackInfo == nullptr || !callbackInfo->active.load()) {
                return;
            }
            ::taihe::env_guard guard;
            if (guard.get_env() == nullptr) {
                FI_HILOGE("Get ANI environment failed");
                return;
            }
            callbackInfo->callback(status);
            if (::taihe::has_error()) {
                FI_HILOGE("Execute callback failed");
            }
        };
        if (!record->handler->PostTask(task, "deviceStatus.dropDetect", 0,
            AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
            FI_HILOGE("Post drop event failed, eventType:%{public}d, "
                      "status:%{public}d",
                      eventType, event->status);
        }
    }
}
#endif // MOTION_ENABLE
} // namespace DeviceStatusV1
} // namespace Msdp
} // namespace OHOS
