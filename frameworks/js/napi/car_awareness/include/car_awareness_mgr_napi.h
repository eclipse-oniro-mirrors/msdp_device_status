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

#ifndef CAR_AWARENESS_MGR_NAPI_H
#define CAR_AWARENESS_MGR_NAPI_H

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>

#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "fi_log.h"

namespace OHOS {
namespace Msdp {
namespace {
    // CarAwareness 能力集Type
    constexpr int32_t INVALID_CAP_TYPE = -1;
    constexpr int32_t TYPE_SPATIAL_MOTION = 101;
    constexpr int32_t TYPE_REALTIME_WEATHER = 102;
    constexpr int32_t TYPE_REFULING = 103;

    constexpr int32_t TYPE_SPATIAL_POINT = 201;
    constexpr int32_t TYPE_SPATIAL_GESTURE = 202;
    constexpr int32_t TYPE_CAR_STATUS = 203;
    constexpr int32_t TYPE_CAR_CFG = 204;
    constexpr int32_t TYPE_HABIT_RECOMMENDATION = 205;

    const std::map<const std::string, int32_t> CAP_TYPE_MAP = {
        { "SpatialMotion", TYPE_SPATIAL_MOTION },
        { "RealTimeWeather", TYPE_REALTIME_WEATHER },
        { "Refueling", TYPE_REFULING },
        { "SpatialPoint", TYPE_SPATIAL_POINT },
        { "SpatialGesture", TYPE_SPATIAL_GESTURE },
        { "CarStatus", TYPE_CAR_STATUS },
        { "CarCfg", TYPE_CAR_CFG },
        { "HabitRecommendation", TYPE_HABIT_RECOMMENDATION }
    };

    const std::vector<std::string> EXPECTED_TYPE_NUMBER_ARG_1 = { "number" };
    const std::vector<std::string> EXPECTED_TYPE_STRING_ARG_1 = { "string" };
    const std::vector<std::string> EXPECTED_TYPE_FUNCTION_ARG_1 = { "function" };
    const std::vector<std::string> EXPECTED_TYPE_FUNCTION_ARG_2 = { "string", "function" };
    const std::vector<std::string> EXPECTED_TYPE_OBJECT_ARG_2 = { "string", "object" };
    const std::vector<std::string> EXPECTED_TYPE_ARG_3 = { "string", "function", "object" };
}

struct CarAwarenessListener {
    std::set<napi_ref> onRefSets;
};

using TriggerFunc = std::function<void(napi_value handler, const std::string&)>;
class CarAwarenessMgrNapi {
public:
    CarAwarenessMgrNapi(napi_env env, napi_value thisVar);
    CarAwarenessMgrNapi() = default;
    virtual ~CarAwarenessMgrNapi();

#ifdef CAR_AWARENESS_ENABLE
    bool AddCallbackEx(int32_t eventType, napi_value listenerHandler, bool isNewHandler);
    bool RemoveAllCallbackEx(int32_t eventType);
    bool RemoveCallbackEx(int32_t eventType, napi_value listenerHandler);
    bool HasCapListener(int32_t eventType);

    void TriggerEvent(const int32_t type, const std::string &data);

protected:
    bool InsertRefEx(std::shared_ptr<CarAwarenessListener> listener,
        const napi_value &handler, bool &isNewHandler);
    bool IsSameValue(const napi_env &env, const napi_value &lhs, const napi_value &rhs);

private:
    void ConvertWeatherInfo(napi_value handler, const std::string &data);
    void ConvertSpatialMotionInfo(napi_value handler, const std::string &data);
    void ConvertRefulingInfo(napi_value handler, const std::string &data);
#endif

protected:
    napi_env env_;
    napi_ref thisVarRef_;
    std::mutex g_listenersMutex;
    std::map<int32_t, std::shared_ptr<CarAwarenessListener>> listenerMap_;
    std::unordered_map<int, TriggerFunc> triggerMap_;
};
} // namespace OHOS
} // namespace Msdp

#endif