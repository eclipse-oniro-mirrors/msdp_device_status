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

#include <ctime>
#include <securec.h>
#include <sys/time.h>
#include "app_event.h"
#include "app_event_processor_mgr.h"
#include "fi_log.h"
#include "msdp_kit_report.h"
#include "msdp_timer_info.h"
#include "time_service_client.h"

#undef LOG_TAG
#define LOG_TAG "MsdpKitReport"

namespace OHOS {
namespace Msdp {
constexpr const char MSDP_KIT_DOMAIN[] = "api_diagnostic";
constexpr const char MSDP_KIT_NAME[] = "api_exec_end";
constexpr const char CONFIG_NAME[] = "ha_app_event";
constexpr const char CONFIG_CONFIG_NAME[] = "SDK_OCG";
constexpr int32_t TIMER_TYPE_WAKEUP = 1 << 1;
constexpr int32_t TIMER_TYPE_EXACT = 1 << 2;
constexpr int64_t INTERVAL_HOUR = 12 * 60 * 60;
constexpr int64_t MS_PER_SEC = 1000;
constexpr int32_t NON_APP_PROCESSOR_ID = -200;

MsdpKitReport::MsdpKitReport()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (isWatching_) {
        return;
    }

    // Create account information
    auto tiSubscribe = std::make_shared<MsdpTimerInfo>();
    tiSubscribe->SetType(TIMER_TYPE_WAKEUP | TIMER_TYPE_EXACT);
    // Configure duplicate reporting
    tiSubscribe->SetRepeat(true);
    // Set the reporting time interval, 12-hour interval
    tiSubscribe->SetInterval(INTERVAL_HOUR * MS_PER_SEC);
    tiSubscribe->SetCallback([this]() { this->SchedulerUpload(); });

    // Create timer
    auto ret = MiscServices::TimeServiceClient::GetInstance()->CreateTimerV9(tiSubscribe, startTimerFd_);
    if (ret != ERR_OK) {
        FI_HILOGE("Failed to create start timer with error code %{public}d", ret);
        return;
    }

    // Start the timer (starting from the current time + 12 hours)
    time_t currentTime = time(nullptr);
    uint64_t nextTriggerTime = (currentTime + INTERVAL_HOUR) * MS_PER_SEC;
    FI_HILOGI("UTC, current: %{public}s, next trigger: %{public}s",
        MsdpTimerInfo::Ts2Str(currentTime).data(),
        MsdpTimerInfo::Ts2Str((currentTime + INTERVAL_HOUR)).data());

    MiscServices::TimeServiceClient::GetInstance()->StartTimerV9(startTimerFd_, nextTriggerTime);
    isWatching_ = true;
}

MsdpKitReport::~MsdpKitReport()
{
    std::lock_guard<std::mutex> lock(mutex_);
    msdpInterfaceEventInfos_.clear();
    if (!isWatching_) {
        return;
    }

    MiscServices::TimeServiceClient::GetInstance()->DestroyTimerV9(startTimerFd_);
    startTimerFd_ = 0;
    isWatching_ = false;
}

void MsdpKitReport::AddEventProcessor()
{
    std::lock_guard<std::mutex> lock(mutex_);
    HiviewDFX::HiAppEvent::ReportConfig config;
    config.name = std::string(CONFIG_NAME);
    config.configName = std::string(CONFIG_CONFIG_NAME);
    processorId_ = HiviewDFX::HiAppEvent::AppEventProcessorMgr::AddProcessor(config);
}

void MsdpKitReport::SchedulerUpload()
{
    FI_HILOGI("SchedulerUpload start");
    // Add data processor
    if (processorId_ == -1) {
        AddEventProcessor();
    }

    // Dot not supported in non-application applications
    if (processorId_ == NON_APP_PROCESSOR_ID) {
        return;
    }
    MsdpInterfaceEventReport();
    FI_HILOGI("SchedulerUpload end");
}

bool MsdpKitReport::UpdateMsdpInterfaceEvent(const MsdpInterfaceEventInfo &msdpInterfaceEventInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (msdpInterfaceEventInfo.apiName.empty() || msdpInterfaceEventInfo.sdkName.empty()) {
        FI_HILOGE("API name or SDK name is empty, apiName size: %{public}zu, sdkName size: %{public}zu",
            msdpInterfaceEventInfo.apiName.size(),
            msdpInterfaceEventInfo.sdkName.size());
        return false;
    }
    auto apiName = msdpInterfaceEventInfo.apiName;
    auto apiIter = msdpInterfaceEventInfos_.find(apiName);
    if (apiIter != msdpInterfaceEventInfos_.end()) {
        apiIter->second = msdpInterfaceEventInfo;
    } else {
        msdpInterfaceEventInfos_.emplace(apiName, msdpInterfaceEventInfo);
    }
    return true;
};

void MsdpKitReport::MsdpInterfaceEventReport()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (msdpInterfaceEventInfos_.size() == 0) {
        FI_HILOGI("msdpInterfaceEventInfos_ is empty");
        return;
    }
    for (const auto &iter : msdpInterfaceEventInfos_) {
        auto msdpInterfaceEventInfo = iter.second;
        HiviewDFX::HiAppEvent::Event event(
            std::string(MSDP_KIT_DOMAIN), std::string(MSDP_KIT_NAME), HiviewDFX::HiAppEvent::BEHAVIOR);
        event.AddParam("api_name", msdpInterfaceEventInfo.apiName);
        event.AddParam("sdk_name", msdpInterfaceEventInfo.sdkName);
        event.AddParam("begin_time", msdpInterfaceEventInfo.beginTime);
        event.AddParam("call_times", msdpInterfaceEventInfo.callTimes);
        event.AddParam("success_times", msdpInterfaceEventInfo.successTimes);
        event.AddParam("max_cost_time", msdpInterfaceEventInfo.maxCostTime);
        event.AddParam("min_cost_time", msdpInterfaceEventInfo.minCostTime);
        event.AddParam("total_cost_time", msdpInterfaceEventInfo.totalCostTime);
        event.AddParam("error_code_types", msdpInterfaceEventInfo.errorCodeType);
        event.AddParam("error_code_num", msdpInterfaceEventInfo.errorCodeNum);
        auto result = Write(event);
        if (result != ERR_OK) {
            FI_HILOGE("MsdpInterfaceEventReport fail, api_name: %{public}s, result: %{public}d",
                msdpInterfaceEventInfo.apiName.c_str(),
                result);
            continue;
        }
    }
    msdpInterfaceEventInfos_.clear();
};
}  // namespace Msdp
}  // namespace OHOS
