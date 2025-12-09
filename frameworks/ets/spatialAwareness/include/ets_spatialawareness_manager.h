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

#ifndef ETS_SPATIALAWARENESS_MANAGER_H
#define ETS_SPATIALAWARENESS_MANAGER_H

#include <iterator>
#include <map>
#include <variant>

#include "ohos.multimodalAwareness.spatialAwareness.proj.hpp"
#include "ohos.multimodalAwareness.spatialAwareness.impl.hpp"
#include "taihe/runtime.hpp"

namespace OHOS {
namespace Msdp {
using namespace taihe;
using TechnologyType = ohos::multimodalAwareness::spatialAwareness::TechnologyType;
using ReportingMode = ohos::multimodalAwareness::spatialAwareness::ReportingMode;
using DistanceMeasurementConfigParams = ohos::multimodalAwareness::spatialAwareness::DistanceMeasurementConfigParams;
using DistanceRank = ohos::multimodalAwareness::spatialAwareness::DistanceRank;
using DistMeasureResponse = ohos::multimodalAwareness::spatialAwareness::DistanceMeasurementResponse;
using PositionRelativeToDoor = ohos::multimodalAwareness::spatialAwareness::PositionRelativeToDoor;
using DoorPositionResponse = ohos::multimodalAwareness::spatialAwareness::DoorPositionResponse;
using callbackType = std::variant<taihe::callback<void(DistMeasureResponse const&)>,
    taihe::callback<void(DoorPositionResponse const&)>>;

enum CDistanceRank : int32_t {
    TYPE_RANK_ULTRA_SHORT_RANGE = 0,
    TYPE_RANK_SHORT_RANGE = 1,
    TYPE_RANK_SHORT_MEDIUM_RANGE = 2,
    TYPE_RANK_MEDIUM_RANGE = 3,
    TYPE_RANK_MAX = 4
};
struct CDistMeasureResponse {
    CDistanceRank rank;
    float distance;
    float confidence;
    const char* deviceId;
};
enum CPositionRelativeToDoor : int32_t {
    TYPE_OF_OUTDOOR = 0,
    TYPE_OF_INDOOR = 1
};
struct CDoorPositionResponse {
    std::uint32_t pinCode;
    CPositionRelativeToDoor position;
    const char* deviceId;
};
struct CDistMeasureData {
    std::string type;
    std::vector<std::string> deviceIds;
    int32_t technologyType;
    int32_t reportMode;
    int32_t reportFreq;
    bool operator < (const CDistMeasureData &other) const
    {
        if (type != other.type) {
            return type < other.type;
        }
        if (deviceIds != other.deviceIds) {
            if (deviceIds.size() == 0) {
                return false;
            } else if (other.deviceIds.size() == 0) {
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

class IDistanceMeasurementListener {
public:
    IDistanceMeasurementListener() = default;
    virtual ~IDistanceMeasurementListener() = default;
    virtual void OnDistanceMeasurementChanged(const CDistMeasureResponse &distMeasureRes);
    virtual void OnDoorIdentifyChanged(const CDoorPositionResponse &identifyRes);
};

typedef int32_t (*SubscribeDistanceMeasurementFunc)(
    std::shared_ptr<OHOS::Msdp::IDistanceMeasurementListener> listener, const CDistMeasureData &cdistMeasureData);
typedef int32_t (*UnsubscribeDistanceMeasurementFunc)(const CDistMeasureData &cdistMeasureData);

struct CallbackObject {
    CallbackObject(callbackType cb, ani_ref ref) : callback(cb), ref(ref)
    {
    }

    ~CallbackObject()
    {
        auto *env = taihe::get_env();
        if (env == nullptr) {
            return;
        }
        env->GlobalReference_Delete(ref);
    }

    callbackType callback;
    ani_ref ref;
};

class GlobalRefGuard {
    ani_env *env_ = nullptr;
    ani_ref ref_ = nullptr;

public:
    GlobalRefGuard(ani_env *env, ani_object obj) : env_(env)
    {
        if (!env_) {
            return;
        }
        if (ANI_OK != env_->GlobalReference_Create(obj, &ref_)) {
            ref_ = nullptr;
        }
    }

    explicit operator bool() const
    {
        return ref_ != nullptr;
    }

    ani_ref get() const
    {
        return ref_;
    }

    ~GlobalRefGuard()
    {
        if (env_ && ref_) {
            env_->GlobalReference_Delete(ref_);
        }
    }

    GlobalRefGuard(const GlobalRefGuard &) = delete;
    GlobalRefGuard &operator=(const GlobalRefGuard &) = delete;
};

class EtsSpatialAwarenessManager : public IDistanceMeasurementListener,
                                   public std::enable_shared_from_this<EtsSpatialAwarenessManager> {
public:
    EtsSpatialAwarenessManager() = default;
    ~EtsSpatialAwarenessManager() = default;

    void OnDistanceMeasurementChanged(const CDistMeasureResponse &distMeasureRes);
    void OnDoorIdentifyChanged(const CDoorPositionResponse &identifyRes);
    void OnDistanceMeasure(DistanceMeasurementConfigParams const& configParams,
        callback_view<void(DistMeasureResponse const&)> callback, uintptr_t opq);
    void OffDistanceMeasure(DistanceMeasurementConfigParams const& configParams, optional_view<uintptr_t> opq);
    void OnIndoorOrOutdoorIdentify(DistanceMeasurementConfigParams const& configParams,
        callback_view<void(DoorPositionResponse const&)> callback, uintptr_t opq);
    void OffIndoorOrOutdoorIdentify(DistanceMeasurementConfigParams const& configParams, optional_view<uintptr_t> opq);
    void Subscribe(DistanceMeasurementConfigParams const& configParams, callbackType &&f, uintptr_t opq,
        const std::string &type);
    void Unsubscribe(DistanceMeasurementConfigParams const& configParams, optional_view<uintptr_t> opq,
        const std::string &type);
    bool RemoveCallback(const std::map<CDistMeasureData, std::vector<std::shared_ptr<CallbackObject>>>::iterator &iter,
        optional_view<uintptr_t> opq);
    bool VerifyParams(DistanceMeasurementConfigParams const& configParams, CDistMeasureData &distMeasureDataSet);
    bool IsValidTechnologyType(int32_t techType);
    bool IsValidReportMode(int32_t reportMode);
    bool IsValidReportFrequency(int32_t reportFrequency);
    bool LoadLibrary();
    void InitDependencyLibrary();
    void RemoveFailCallback(ani_env *env, const CDistMeasureData &distMeasureDataSet,
        uintptr_t opq, std::map<CDistMeasureData, std::vector<std::shared_ptr<CallbackObject>>> &jsCbMap);
    bool SubscribeDistanceMeasurement(const CDistMeasureData &cdistMeasureData);
    bool UnsubscribeDistanceMeasurement(const CDistMeasureData &cdistMeasureData);

    static std::shared_ptr<EtsSpatialAwarenessManager> GetInstance();

private:
    void* distanceMeasurementHandle = nullptr;
    SubscribeDistanceMeasurementFunc subscribeDistanceMeasurementFunc = nullptr;
    UnsubscribeDistanceMeasurementFunc unsubscribeDistanceMeasurementFunc = nullptr;
    std::recursive_mutex mutex_;
    std::map<CDistMeasureData, std::vector<std::shared_ptr<CallbackObject>>> jsCbMap_;
    CDistMeasureData distMeasureDataSet_;
};
} // Msdp
} // OHOS
#endif // ETS_SPATIALAWARENESS_MANAGER_H