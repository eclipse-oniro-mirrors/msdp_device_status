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

#ifndef BEHAVIOR_AWARENESS_DATA_H
#define BEHAVIOR_AWARENESS_DATA_H

#include <cstdint>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace BehaviorAwareness {
constexpr int32_t COMMON_NOT_SYSTEM_APP = 202;
constexpr int32_t PARAM_EXCEPTION = 401;
constexpr int32_t DEVICE_NOT_SUPPORT = 801;
constexpr int32_t SERVICE_EXCEPTION = 32500001;
constexpr int32_t UNSUBSCRIBE_EXCEPTION = 32500003;

constexpr const char *DEVICE_TYPE_PARA_NAME = "const.product.devicetype";
constexpr const char *SUPPORTED_DEVICE_TYPE = "phone";

enum class PerceptionDomain : int32_t {
    HABIT_AWARENESS = 0,
};

enum class PatternType : int32_t {
    TIME_PATTERN = 0,
    LOCATION_PATTERN = 1,
    EVENT_PATTERN = 2,
};

enum class FeedbackType : int32_t {
    ACCEPT = 0,
    IGNORE = 1,
    REJECT = 2,
    EDIT = 3,
    NOT_PUSHED = 4,
};

struct SubscribeOptions {
    PerceptionDomain domain { PerceptionDomain::HABIT_AWARENESS };
    std::vector<int32_t> patternTypes;
};

struct PerceptionEventData {
    std::string perceptionEventId;
    PerceptionDomain domain { PerceptionDomain::HABIT_AWARENESS };
    int32_t confidence { 0 };
    int64_t generateTime { 0 };
    std::string payload;
};

struct FeedbackData {
    std::string perceptionEventId;
    FeedbackType feedbackType { FeedbackType::ACCEPT };
    int64_t feedbackTime { 0 };
};

inline std::string BuildSubscriptionKey(const SubscribeOptions &options)
{
    std::ostringstream oss;
    oss << static_cast<int32_t>(options.domain);
    for (int32_t pt : options.patternTypes) {
        oss << ":" << pt;
    }
    return oss.str();
}

inline const std::map<int32_t, std::string>& GetErrorMsgMap()
{
    static const std::map<int32_t, std::string> messages = {
        { COMMON_NOT_SYSTEM_APP, "Permission verification failed. A non-system application uses the system API." },
        { PARAM_EXCEPTION, "Parameter error. Possible causes: 1. Mandatory parameters are left unspecified; "
            "2. Incorrect parameter types; 3. Parameter verification failed." },
        { DEVICE_NOT_SUPPORT, "Capability not supported. Possible causes: "
            "1. The hardware does not support the capability." },
        { SERVICE_EXCEPTION, "Service exception." }, { UNSUBSCRIBE_EXCEPTION, "Unsubscription failed." },
    };
    return messages;
}

inline std::string GetErrMsg(int32_t errCode)
{
    auto& messages = GetErrorMsgMap();
    auto iter = messages.find(errCode);
    if (iter != messages.end()) {
        return iter->second;
    }
    return "";
}
} // namespace BehaviorAwareness
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // BEHAVIOR_AWARENESS_DATA_H
