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

#include "napi_event_utils.h"

#include "app_event.h"
#include "app_event_processor_mgr.h"

namespace OHOS {
namespace Msdp {
namespace {
const std::string SDK_NAME = "MultimodalAwarenessKit";
constexpr int32_t TIMEOUT = 90;
constexpr int32_t ROW = 30;
}

int64_t NapiEventUtils::AddProcessor()
{
    HiviewDFX::HiAppEvent::ReportConfig config;
    config.name = "ha_app_event";
    config.appId = "com_huawei_hmos_sdk_ocg";
    config.routeInfo = "AUTO";
    config.triggerCond.timeout = TIMEOUT;
    config.triggerCond.row = ROW;
    config.eventConfigs.clear();
    {
        OHOS::HiviewDFX::HiAppEvent::EventConfig event1;
        event1.domain = "api_diagnostic";
        event1.name = "api_exec_end";
        event1.isRealTime = false;
        config.eventConfigs.push_back(event1);
    }
    {
        OHOS::HiviewDFX::HiAppEvent::EventConfig event2;
        event2.domain = "api_diagnostic";
        event2.name = "api_called_stat";
        event2.isRealTime = true;
        config.eventConfigs.push_back(event2);
    }
    {
        OHOS::HiviewDFX::HiAppEvent::EventConfig event3;
        event3.domain = "api_diagnostic";
        event3.name = "api_called_stat_cnt";
        event3.isRealTime = true;
        config.eventConfigs.push_back(event3);
    }
    return HiviewDFX::HiAppEvent::AppEventProcessorMgr::AddProcessor(config);
}

void NapiEventUtils::WriteEndEvent(const std::string& transId, const std::string& apiName, const int64_t beginTime,
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
    Write(event);
}

int64_t NapiEventUtils::GetSysClockTime()
{
    return std::chrono::time_point_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now()).time_since_epoch().count();
}
} // namespace Msdp
} // namespace OHOS