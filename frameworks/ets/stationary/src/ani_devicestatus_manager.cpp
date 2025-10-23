/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "ani_devicestatus_manager.h"

#include "ani_devicestatus_event.h"
#include "devicestatus_client.h"
#include "devicestatus_define.h"
#include "fi_log.h"
#include "stationary_data.h"
#include "stationary_manager.h"

#undef LOG_TAG
#define LOG_TAG "AniDeviceStatusManager"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
constexpr int32_t NANO { 1000000000 };
std::map<int32_t, sptr<IRemoteDevStaCallback>> AniDeviceStatusManager::callbacks_;

AniDeviceStatusCallback::AniDeviceStatusCallback()
{}

AniDeviceStatusCallback::~AniDeviceStatusCallback()
{}

void AniDeviceStatusCallback::OnDeviceStatusChanged(const Data& devicestatusData)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(backMutex_);
    FI_HILOGD("devicestatusData.type:%{public}d, devicestatusData.value:%{public}d",
        devicestatusData.type, devicestatusData.value);
    int32_t type = static_cast<int32_t>(devicestatusData.type);
    int32_t value = static_cast<int32_t>(devicestatusData.value);
    FI_HILOGD("type:%{public}d, value:%{public}d", type, value);
    AniDeviceStatusEvent::GetInstance()->OnDeviceStatusChangedDone(type, value, false);
}

AniDeviceStatusManager::AniDeviceStatusManager()
{
    DeviceStatusClient::GetInstance().RegisterDeathListener([this] {
        FI_HILOGI("Receive death notification");
        callbacks_.clear();
        ClearEventMap();
    });
}

AniDeviceStatusManager::~AniDeviceStatusManager()
{
}

std::shared_ptr<AniDeviceStatusManager> AniDeviceStatusManager::GetInstance()
{
    static std::once_flag flag;
    static std::shared_ptr<AniDeviceStatusManager> instance_;

    std::call_once(flag, []() {
        instance_ = std::make_shared<AniDeviceStatusManager>();
    });
    return instance_;
}

int32_t AniDeviceStatusManager::ConvertTypeToInt(const std::string &type)
{
    if (type == "absoluteStill") {
        return Type::TYPE_ABSOLUTE_STILL;
    } else if (type == "horizontalPosition") {
        return Type::TYPE_HORIZONTAL_POSITION;
    } else if (type == "verticalPosition") {
        return Type::TYPE_VERTICAL_POSITION;
    } else if (type == "still") {
        return Type::TYPE_STILL;
    } else if (type == "relativeStill") {
        return Type::TYPE_RELATIVE_STILL;
    } else if (type == "carBluetooth") {
        return Type::TYPE_CAR_BLUETOOTH;
    } else {
        return Type::TYPE_INVALID;
    }
}

ActivityEvent AniDeviceStatusManager::ConvertEventToInt(ActivityEvent_t event)
{
    switch (event.get_key()) {
        case ActivityEvent_t::key_t::ENTER:
            return ActivityEvent::ENTER;
        case ActivityEvent_t::key_t::EXIT:
            return ActivityEvent::EXIT;
        case ActivityEvent_t::key_t::ENTER_EXIT:
            return ActivityEvent::ENTER_EXIT;
        default:
            return ActivityEvent::EVENT_INVALID;
    }
}

void AniDeviceStatusManager::GetDeviceStatus(const std::string action,
    taihe::callback_view<void(ActivityResponse_t const&)> f, uintptr_t opq)
{
    int32_t type = ConvertTypeToInt(action);
    if ((type != Type::TYPE_STILL) && (type != Type::TYPE_RELATIVE_STILL)) {
        taihe::set_business_error(PARAM_ERROR, "Type is illegal");
        return;
    }
    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    ani_ref callbackRef = nullptr;
    ani_env *env = taihe::get_env();
    if (env == nullptr || ANI_OK != env->GlobalReference_Create(callbackObj, &callbackRef)) {
        FI_HILOGE("%{public}s ani_env is nullptr or GlobalReference_Create failed", LOG_TAG);
        return;
    }
    if (!AniDeviceStatusEvent::GetInstance()->On(type, callbackRef, true)) {
        FI_HILOGE("type:%{public}d already exists", type);
        return;
    }
    Data devicestatusData = StationaryManager::GetInstance()->GetDeviceStatusData(static_cast<Type>(type));
    if (devicestatusData.type == Type::TYPE_INVALID) {
        taihe::set_business_error(SERVICE_EXCEPTION, "Once:Failed to get device status data");
    }
    AniDeviceStatusEvent::GetInstance()->OnDeviceStatusChangedDone(devicestatusData.type, devicestatusData.value, true);
    AniDeviceStatusEvent::GetInstance()->OffOnce(devicestatusData.type, callbackRef);
}

void AniDeviceStatusManager::SubscribeDeviceStatusCallback(int32_t type, int32_t event, int32_t latency, uintptr_t opq)
{
    CALL_DEBUG_ENTER;
    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    ani_ref callbackRef = nullptr;
    ani_env *env = taihe::get_env();
    if (env == nullptr || ANI_OK != env->GlobalReference_Create(callbackObj, &callbackRef)) {
        FI_HILOGE("%{public}s ani_env is nullptr or GlobalReference_Create failed", LOG_TAG);
        return;
    }
    if (!AniDeviceStatusEvent::GetInstance()->On(type, callbackRef, false)) {
        FI_HILOGE("type:%{public}d already exists", type);
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    auto callbackIter = callbacks_.find(type);
    if (callbackIter != callbacks_.end()) {
        FI_HILOGD("Callback exists");
        return;
    }
    sptr<IRemoteDevStaCallback> callback = new (std::nothrow) AniDeviceStatusCallback();
    CHKPV(callback);
    int32_t subscribeRet = StationaryManager::GetInstance()->SubscribeCallback(static_cast<Type>(type),
        static_cast<ActivityEvent>(event), static_cast<ReportLatencyNs>(latency), callback);
    if (subscribeRet != RET_OK) {
        taihe::set_business_error(SERVICE_EXCEPTION, "On:Failed to SubscribeCallback");
        return;
    }
    auto ret = callbacks_.insert(std::pair<int32_t, sptr<IRemoteDevStaCallback>>(type, callback));
    if (!ret.second) {
        FI_HILOGE("Failed to insert");
    }
    return;
}

void AniDeviceStatusManager::SubscribeDeviceStatus(const std::string action, ActivityEvent_t event,
    int64_t reportLatencyNs, ::taihe::callback_view<void(ActivityResponse_t const&)> f, uintptr_t opq)
{
    int32_t type = ConvertTypeToInt(action);
    ActivityEvent actEvent = ConvertEventToInt(event);
    int64_t latencyMode = reportLatencyNs / NANO;
    FI_HILOGD("type:%{public}d, event:%{public}d, latency:%{public}" PRId64, type, actEvent, latencyMode);
    if ((type != Type::TYPE_STILL) && (type != Type::TYPE_RELATIVE_STILL)) {
        taihe::set_business_error(PARAM_ERROR, "Type is illegal");
        return;
    }
    if ((event < ActivityEvent::ENTER) || (event > ActivityEvent::ENTER_EXIT)) {
        taihe::set_business_error(PARAM_ERROR, "Event is illegal");
        return;
    }
    if ((latencyMode < ReportLatencyNs::SHORT) || (latencyMode > ReportLatencyNs::LONG)) {
        taihe::set_business_error(PARAM_ERROR, "Latency is illegal");
        return;
    }
    SubscribeDeviceStatusCallback(type, actEvent, latencyMode, opq);
}

void AniDeviceStatusManager::UnsubscribeCallback(int32_t type, int32_t event)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> lock(mutex_);
    auto callbackIter = callbacks_.find(type);
    if (callbackIter == callbacks_.end()) {
        FI_HILOGD("No existed callback");
        return;
    }
    int32_t unsubscribeRet = StationaryManager::GetInstance()->UnsubscribeCallback(static_cast<Type>(type),
        static_cast<ActivityEvent>(event), callbackIter->second);
    if (unsubscribeRet != RET_OK) {
        taihe::set_business_error(SERVICE_EXCEPTION, "Off:Failed to UnsubscribeCallback");
    }
    callbacks_.erase(type);
    return;
}

void AniDeviceStatusManager::UnsubscribeDeviceStatus(const std::string action, ActivityEvent_t event,
    taihe::optional_view<uintptr_t> opq)
{
    int32_t type = ConvertTypeToInt(action);
    if ((type != Type::TYPE_STILL) && (type != Type::TYPE_RELATIVE_STILL)) {
        taihe::set_business_error(PARAM_ERROR, "Type is illegal");
        return;
    }
    ActivityEvent actEvent = ConvertEventToInt(event);
    if ((event < ActivityEvent::ENTER) || (event > ActivityEvent::ENTER_EXIT)) {
        taihe::set_business_error(PARAM_ERROR, "Event is illegal");
        return;
    }
    FI_HILOGD("type:%{public}d, event:%{public}d", type, actEvent);
    if (!opq.has_value()) {
        if (!AniDeviceStatusEvent::GetInstance()->RemoveAllCallback(type)) {
            FI_HILOGE("Callback type is not exist");
            return;
        }
        UnsubscribeCallback(type, actEvent);
    }
    ani_object callbackObj = reinterpret_cast<ani_object>(opq.value());
    ani_ref callbackRef;
    ani_env *env = taihe::get_env();
    if (env == nullptr || env->GlobalReference_Create(callbackObj, &callbackRef) != ANI_OK) {
        FI_HILOGE("ani_env is nullptr or GlobalReference_Create failed");
        return;
    }
    if (!AniDeviceStatusEvent::GetInstance()->Off(type, callbackRef)) {
        FI_HILOGE("Not ready to unsubscribe for type:%{public}d", type);
        return;
    }
    UnsubscribeCallback(type, actEvent);
    return;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS