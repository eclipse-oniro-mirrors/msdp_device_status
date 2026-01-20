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
#include <chrono>
#include <map>
#include <string>

#include "app_event.h"
#include "app_event_processor_mgr.h"
#include "ani_error_utils.h"
#include "ani_devicestatus_observer.h"
#include "ohos.multimodalAwareness.deviceStatus.proj.hpp"
#include "ohos.multimodalAwareness.deviceStatus.impl.hpp"
#include "devicestatus_callback_stub.h"
#include "devicestatus_define.h"
#include "iremote_dev_sta_callback.h"
#include "stationary_data.h"
#include "stationary_manager.h"
#include "fi_log.h"
#include "taihe/runtime.hpp"

#undef LOG_TAG
#define LOG_TAG "AniTaiheImpl"

namespace {
using namespace OHOS;
using namespace OHOS::Msdp;
using namespace OHOS::Msdp::DeviceStatusV1;

const std::string SDK_NAME = "MultimodalAwarenessKit";
constexpr int32_t EVENT_NOT_SUPPORT = -200;
constexpr int32_t EVENT_NO_INITIALIZE = -1;

static std::mutex gCallbacksMutex_;
static std::map<DeviceStatus::Type, sptr<ani_observerutils::AniDeviceStatusCallback>> gCallbacks_;

static int64_t g_processorId = -1;

static int64_t GetSysClockTime()
{
    return std::chrono::time_point_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now()).time_since_epoch().count();
}

static int64_t HiviewAddProcessor()
{
    HiviewDFX::HiAppEvent::ReportConfig config;
    config.name = "ha_app_event";
    config.configName = "SDK_OCG";
    return HiviewDFX::HiAppEvent::AppEventProcessorMgr::AddProcessor(config);
}

static void HiviewWriteEndEvent(const std::string& transId, const std::string& apiName, const int64_t beginTime,
    const int result, const int errCode)
{
    HiviewDFX::HiAppEvent::Event event("api_diagnostic", "api_exec_end", HiviewDFX::HiAppEvent::BEHAVIOR);
    event.AddParam("trans_id", transId);
    event.AddParam("api_name", apiName);
    event.AddParam("sdk_name", SDK_NAME);
    event.AddParam("begin_time", beginTime);
    event.AddParam("end_time", GetSysClockTime());
    event.AddParam("result", result);
    event.AddParam("error_code", errCode);
    HiviewDFX::HiAppEvent::Write(event);
}

bool IsTaiheStandCallbackExist(JsOnSteadyStandingCallbackType const& taiheCallback)
{
    auto iter = gCallbacks_.find(DeviceStatus::Type::TYPE_STAND);
    if (iter == gCallbacks_.end()) {
        return false;
    }
    auto staCallback = iter->second;
    if (staCallback == nullptr) {
        return false;
    }
    return staCallback->IsTaiheStandCallbackExist(taiheCallback);
}

int32_t SubscribeCallback(ani_env* env, DeviceStatus::Type type,
    sptr<ani_observerutils::AniDeviceStatusCallback> &statusCallback)
{
    auto iter = gCallbacks_.find(type);
    int32_t ret = RET_OK;
    if (iter == gCallbacks_.end()) {
        FI_HILOGI("Don't find TYPE_STAND callback, create");
        auto callback = sptr<ani_observerutils::AniDeviceStatusCallback>::MakeSptr();
        ret = DeviceStatus::StationaryManager::GetInstance().SubscribeCallback(type,
            DeviceStatus::ActivityEvent::EVENT_INVALID, DeviceStatus::ReportLatencyNs::Latency_INVALID, callback);
        if (ret == RET_OK) {
            gCallbacks_.insert(std::make_pair(type, callback));
            statusCallback = callback;
        }
    } else {
        statusCallback = iter->second;
        ret = DeviceStatus::StationaryManager::GetInstance().SubscribeCallback(type,
            DeviceStatus::ActivityEvent::EVENT_INVALID, DeviceStatus::ReportLatencyNs::Latency_INVALID, iter->second);
    }
    FI_HILOGI("SubscribeCallback to native ret %{public}d", ret);
    return ret;
}

void OnSteadyStandingDetect(
    ::taihe::callback_view<void(::ohos::multimodalAwareness::deviceStatus::SteadyStandingStatus)> f)
{
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        ani_errorutils::ThrowDeviceStatusErr(SUBSCRIBE_EXCEPTION);
        return;
    }

    std::lock_guard<std::mutex> guard(gCallbacksMutex_);
    JsOnSteadyStandingCallbackType taiheCallback = f;
    if (IsTaiheStandCallbackExist(taiheCallback)) {
        FI_HILOGE("failed to subscribe, callback existed");
        ani_errorutils::ThrowDeviceStatusErr(SUBSCRIBE_EXCEPTION);
        return;
    }
    if (g_processorId == EVENT_NO_INITIALIZE) {
        g_processorId = HiviewAddProcessor();
    }
    int64_t beginTime = GetSysClockTime();
    std::string transId = std::string("transId_") + std::to_string(std::rand());
    sptr<ani_observerutils::AniDeviceStatusCallback> statusCallback = nullptr;
    int32_t ret = SubscribeCallback(env, DeviceStatus::Type::TYPE_STAND, statusCallback);
    if (ret == DEVICE_EXCEPTION) {
        FI_HILOGE("failed to subscribe, Device not support");
        ani_errorutils::ThrowDeviceStatusErr(DEVICE_EXCEPTION);
        return;
    } else if (ret != RET_OK || statusCallback == nullptr) {
        FI_HILOGE("failed to subscribe, Subscribe failed");
        ani_errorutils::ThrowDeviceStatusErr(SUBSCRIBE_EXCEPTION);
        return;
    }
    statusCallback->AddTaiheStandCallback(taiheCallback);
    if (g_processorId == EVENT_NOT_SUPPORT) {
        FI_HILOGW("Non-applications do not support breakpoint");
    } else {
        std::string apiName = "deviceStatus.steadyStandingDetect.on";
        HiviewWriteEndEvent(transId, apiName, beginTime, 0, 0);
    }
}

void OffSteadyStandingDetect(::taihe::optional_view<
    ::taihe::callback<void(::ohos::multimodalAwareness::deviceStatus::SteadyStandingStatus)>> callbackOpt)
{
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        ani_errorutils::ThrowDeviceStatusErr(UNSUBSCRIBE_EXCEPTION);
        return;
    }

    std::lock_guard<std::mutex> guard(gCallbacksMutex_);
    std::optional<JsOnSteadyStandingCallbackType> para;
    if (callbackOpt.has_value()) {
        para = callbackOpt.value();
    }
    auto iter = gCallbacks_.find(DeviceStatus::Type::TYPE_STAND);
    if (iter == gCallbacks_.end()) {
        FI_HILOGE("No TYPE_STAND callback");
        ani_errorutils::ThrowDeviceStatusErr(UNSUBSCRIBE_EXCEPTION);
        return;
    }
    auto staCallback = iter->second;
    if (staCallback == nullptr) {
        FI_HILOGE("No TYPE_STAND callback");
        ani_errorutils::ThrowDeviceStatusErr(UNSUBSCRIBE_EXCEPTION);
        return;
    }
    bool isEmpty = false;
    bool modified = staCallback->RemoveTaiheStandCallback(para, isEmpty);
    if (!modified) {
        ani_errorutils::ThrowDeviceStatusErr(SERVICE_EXCEPTION);
        return;
    }
    if (!isEmpty) {
        return;
    }
    int32_t ret = DeviceStatus::StationaryManager::GetInstance().UnsubscribeCallback(
        DeviceStatus::Type::TYPE_STAND, DeviceStatus::ActivityEvent::EVENT_INVALID, staCallback);
    FI_HILOGI("OffSteadyStandingDetect, no standcallback left, unregister ret %{public}d", ret);
    if (ret == RET_OK) {
        gCallbacks_.erase(iter);
        return;
    }
    if (ret == DEVICE_EXCEPTION) {
        FI_HILOGE("failed to unsubscribe, Device not support");
        ani_errorutils::ThrowDeviceStatusErr(DEVICE_EXCEPTION);
    } else {
        FI_HILOGE("failed to unsubscribe");
        ani_errorutils::ThrowDeviceStatusErr(UNSUBSCRIBE_EXCEPTION);
    }
}

::ohos::multimodalAwareness::deviceStatus::DeviceRotationRadian getDeviceRotationRadianSync()
{
    double x = 0.0;
    double y = 0.0;
    double z = 0.0;
    DeviceStatus::DevicePostureData postureData;
    auto result = DeviceStatus::StationaryManager::
        GetInstance().GetDevicePostureDataSync(postureData);
    if (result != RET_OK ) {
        FI_HILOGE("GetDevicePostureDataSync err, result:%{public}d", result);
        if (result == NO_SYSTEM_API || result == DEVICE_EXCEPTION) {
            ani_errorutils::ThrowDeviceStatusErr(result);
        } else {
            ani_errorutils::ThrowDeviceStatusErr(SERVICE_EXCEPTION);
        }
    } else {
        x = postureData.rollRad;
        y = postureData.pitchRad;
        z = postureData.yawRad;
    }
    auto deviceRotationRadian = ::ohos::multimodalAwareness::deviceStatus::DeviceRotationRadian {
        std::move(x),
        std::move(y),
        std::move(z),
    };
    return deviceRotationRadian;
}

}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_OnSteadyStandingDetect(OnSteadyStandingDetect);
TH_EXPORT_CPP_API_OffSteadyStandingDetect(OffSteadyStandingDetect);
TH_EXPORT_CPP_API_getDeviceRotationRadianSync(getDeviceRotationRadianSync);
// NOLINTEND
