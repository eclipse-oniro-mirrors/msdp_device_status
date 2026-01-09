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

#include "fi_log.h"
#include "msdp_timer_info.h"

#undef LOG_TAG
#define LOG_TAG "MsdpTimerInfo"

namespace OHOS {
namespace Msdp {
std::string MsdpTimerInfo::Ts2Str(uint64_t timestamp)
{
    if (timestamp > std::numeric_limits<time_t>::max()) {
        return "Invalid time";
    }

    time_t seconds = static_cast<time_t>(timestamp);
    struct tm tm_struct;
    struct tm *tm_ptr = gmtime_r(&seconds, &tm_struct);

    if (tm_ptr == nullptr) {
        return "Invalid time";
    }

    char buffer[255] = "\0";
    if (strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_ptr) == 0) {
        return "Invalid time format";
    }
    return std::string(buffer);
}

void MsdpTimerInfo::OnTrigger()
{
    FI_HILOGI("OnTrigger enter");
    if (callback_) {
        callback_();
    }
    FI_HILOGI("OnTrigger complete");
}
}  // namespace Msdp
}  // namespace OHOS