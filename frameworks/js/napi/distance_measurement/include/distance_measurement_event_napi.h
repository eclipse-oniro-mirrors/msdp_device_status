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

#ifndef DISTANCE_MEASUREMENT_EVENT_NAPI_H
#define DISTANCE_MEASUREMENT_EVENT_NAPI_H

#include <bitset>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <unordered_set>
#include "fi_log.h"
#include "napi/native_api.h"
#include "parcel.h"


namespace OHOS {
namespace Msdp {
struct CDistMeasureData {
        std::string type;
        std::vector<std::string> deviceIds = {};
        int32_t technologyType = -1;
        int32_t reportMode = -1;
        int32_t reportFreq = -1;
        bool operator < (const CDistMeasureData &other) const
        {
            if (type != other.type) {
                return type < other.type;
            }
            if (deviceIds != other.deviceIds) {
                if (deviceIds.size() == 0) {
                    return false;
                } else if  (other.deviceIds.size() == 0) {
                    return true;
                } else {
                    return deviceIds < other.deviceIds;
                }
            }
            if (technologyType != other.technologyType) {
                return technologyType < other.technologyType;
            }
            if (reportMode != other.reportMode) {
                return reportMode < other.reportMode;
            }
            return reportFreq < other.reportFreq;
        }
    };
class DistanceMeasurementListener {
public:
    napi_ref handlerRef = nullptr;
};

class DistanceMeasurementEventNapi {
public:
    enum DistanceRank : int32_t {
        TYPE_RANK_ULTRA_SHORT_RANGE = 0,
        TYPE_RANK_SHORT_RANGE = 1,
        TYPE_RANK_SHORT_MEDIUM_RANGE = 2,
        TYPE_RANK_MEDIUM_RANGE = 3,
        TYPE_RANK_MAX = 4,
    };
    enum TechnologyType : int32_t {
        BLE_RSSI = 0,
        WIFI_RSSI = 1,
        ULTRASOUND = 2,
        NEARLINK = 3,
        WIFI_BLE_RSSI = 4,
    };
    enum ReportingMode : int32_t {
        REPORT_MODE_PERIODIC_REPORTING = 0,
        REPORT_MODE_TRIGGERED_REPORTING = 1,
    };
    enum PositionRelativeToDoor : int32_t {
        TYPE_OF_OUTDOOR = 0,
        TYPE_OF_INDOOR = 1,
    };
    struct DistanceMeasurementConfigParams {
        std::vector<std::string> deviceList;
        int32_t techType;
        int32_t reportMode;
        int32_t reportFrequency = -1;
    };
    using RankMaskType = std::bitset<DistanceRank::TYPE_RANK_MAX>;
    struct CDistMeasureResponse {
        DistanceRank rank;
        float distance;
        float confidence;
        std::string deviceId;
    };
    struct CDoorPositionResponse {
        std::uint32_t pinCode;
        PositionRelativeToDoor position;
        std::string deviceId;
    };
    
    DistanceMeasurementEventNapi(napi_env env, napi_value thisVar, int32_t callbackIdx);
    DistanceMeasurementEventNapi() = default;
    virtual ~DistanceMeasurementEventNapi();
    virtual void UpdateEnv(napi_env env, napi_value jsThis);
    virtual void ClearEnv();
    virtual bool AddCallback(const CDistMeasureData &cdistMeasureData, napi_value handler);
    virtual void RemoveCallback(const CDistMeasureData &cdistMeasureData);
    virtual void OnDistMeasureEvent(size_t argc, const napi_value *argv, const std::string &type);
protected:
    std::mutex mutex_;
    std::atomic<napi_env> env_ {nullptr};
    int32_t callbackIdx_;
    napi_ref thisVarRef_ {nullptr};
    CDistMeasureData distMeasureDataSet_;

    std::map<CDistMeasureData, std::shared_ptr<DistanceMeasurementListener>> distMeasureEventMap_;

    bool IsSameValue(const napi_env &env, const napi_value &lhs, const napi_value &rhs);
    bool InsertRef(std::shared_ptr<DistanceMeasurementListener> listener, const napi_value &handler);
};
} // namespace Msdp
} // namespace OHOS
#endif // DISTANCE_MEASUREMENT_EVENT_NAPI_H