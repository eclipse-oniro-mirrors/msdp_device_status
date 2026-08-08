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

#ifndef CAR_AWARENESS_SERVER_H
#define CAR_AWARENESS_SERVER_H

#include <map>
#include <mutex>
#include <set>

#include "car_awareness_callback_stub.h"
#include "car_awareness_type.h"
#include "i_plugin.h"
#include "i_car_awareness_mgr.h"
#include "icar_awareness_callback.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
struct CarAwarenessPluginHandle {
    void *handle = nullptr;
    CarAwareness::ICarAwarenessMgr *pAlgorithm = nullptr;
    CarAwareness::CreateCarAwarenessMgrFuncPtr create = nullptr;
    void (*destroy)() = nullptr;
    void Clear()
    {
        handle = nullptr;
        pAlgorithm = nullptr;
        create = nullptr;
        destroy = nullptr;
    }
};

class CarAwarenessRemoteDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit CarAwarenessRemoteDeathRecipient(std::function<void(const wptr<IRemoteObject> &)> func) : func_(func)
    {}
    ~CarAwarenessRemoteDeathRecipient() = default;
    void OnRemoteDied(const wptr<IRemoteObject> &remote) override
    {
        if (func_ != nullptr) {
            func_(remote);
        }
    }

private:
    std::function<void(const wptr<IRemoteObject> &)> func_ = nullptr;
};

struct CarAwarenessClientInfo {
    pid_t pid;
    sptr<ICarAwarenessCallback> cb;
};

class CarAwarenessServer {
public:
    CarAwarenessServer();
    virtual ~CarAwarenessServer();
    int32_t SubscribeCapability(const CallingContext &context, int32_t type, const CarAwarenessOption &option,
                                const sptr<ICarAwarenessCallback> &cb);
    int32_t UnSubscribeCapability(const CallingContext &context, int32_t type, const CarAwarenessOption &option,
                                  const sptr<ICarAwarenessCallback> &cb);
    int32_t UpdateSpatialActionStatus(const CallingContext &context, int32_t eventId);
    int32_t UpdateSpatialActionZone(const CallingContext &context, int32_t zoneId);
    int32_t GetSupportCapabilityList(const CallingContext &context, std::vector<std::string> &capabilities);
    int32_t GetCarAwareness(const CallingContext &context, int32_t type, const CarAwarenessOption &option,
                            std::vector<CarAwarenessEvent> &events);

private:
    int32_t LoadAlgoLib();
    int32_t UnloadAlgoLib();
    void OnCarAwarenessCallbackDied(const wptr<IRemoteObject> &remote);
    bool AddDeathRecipient(const sptr<ICarAwarenessCallback> &cb);
    void RemoveDeathRecipient(const sptr<ICarAwarenessCallback> &cb);
    bool EraseCallback(const std::string &featureName, pid_t clientPid);
    int32_t CheckPermission(const CallingContext &context, const std::string &requiredPermission);
    int32_t CheckSubPermissionByType(const CallingContext &context, int32_t type);
    void OnResultFromAlgo(const std::string &featureName, const std::string &result);
    int32_t AddClientToCallbacks(const std::string &featureName, CarAwarenessClientInfo &info);
    void UnSubscribeAlgo(const std::string &featureName);
    bool CheckSystemCall(const CallingContext &context);
    int32_t SubscribeAlgo(const std::string &featureName);

    sptr<IRemoteObject::DeathRecipient> deathRecipient_{nullptr};
    std::mutex algoMtx_;
    std::mutex callbackMtx_;
    std::map<std::string, std::vector<CarAwarenessClientInfo>> callbacks_;
    CarAwarenessPluginHandle algoHandle_;
    CarAwareness::CarAwarenessCallback algoCb_ = nullptr;
};
}  // namespace DeviceStatus
}  // namespace Msdp
}  // namespace OHOS
#endif  // CAR_AWARENESS_SERVER_H