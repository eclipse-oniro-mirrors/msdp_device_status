/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef DEVICESTATUS_MANAGER_H
#define DEVICESTATUS_MANAGER_H

#include <set>
#include <map>

#include "accesstoken_kit.h"
#include "boomerang_callback.h"
#include "boomerang_data.h"
#include "devicestatus_msdp_client_impl.h"
#include "stationary_callback.h"
#include "stationary_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace Security::AccessToken;
class DeviceStatusService;
class DeviceStatusManager {
public:
    DeviceStatusManager() = default;
    ~DeviceStatusManager() = default;

    class DeviceStatusCallbackDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        DeviceStatusCallbackDeathRecipient() = default;
        virtual void OnRemoteDied(const wptr<IRemoteObject> &remote);
        virtual ~DeviceStatusCallbackDeathRecipient() = default;
    };

    class BoomerangCallbackDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        BoomerangCallbackDeathRecipient(DeviceStatusManager* deviceStatusManager) : manager_(deviceStatusManager) {}
        virtual void OnRemoteDied(const wptr<IRemoteObject> &remote);
        virtual ~BoomerangCallbackDeathRecipient() = default;
    private:
        DeviceStatusManager* manager_;
        friend class DeviceStatusManager;
    };

    bool Init();
    bool Enable(Type type);
    bool InitAlgoMngrInterface(Type type);
    bool Disable(Type type);
    int32_t InitDataCallback();
    int32_t NotifyDeviceStatusChange(const Data &devicestatusData);
    void Subscribe(Type type, ActivityEvent event, ReportLatencyNs latency, sptr<IRemoteDevStaCallback> callback);
    void Unsubscribe(Type type, ActivityEvent event, sptr<IRemoteDevStaCallback> callback);
    void Subscribe(BoomerangType type, std::string bundleName, sptr<IRemoteBoomerangCallback> callback);
    void Unsubscribe(BoomerangType type, std::string bundleName, sptr<IRemoteBoomerangCallback> callback);
    int32_t NotifyMedata(std::string bundleName, sptr<IRemoteBoomerangCallback> callback);
    void SubmitMetadata(std::string metadata);
    void BoomerangEncodeImage(std::shared_ptr<Media::PixelMap> pixelMap, std::string matedata,
        sptr<IRemoteBoomerangCallback> callback);
    void BoomerangDecodeImage(std::shared_ptr<Media::PixelMap> pixelMap, sptr<IRemoteBoomerangCallback> callback);
    Data GetLatestDeviceStatusData(Type type);
    int32_t MsdpDataCallback(const Data &data);
    int32_t LoadAlgorithm();
    int32_t UnloadAlgorithm();
    int32_t GetPackageName(AccessTokenID tokenId, std::string &packageName);

private:
    struct classcomp {
        bool operator()(sptr<IRemoteDevStaCallback> left, sptr<IRemoteDevStaCallback> right) const
        {
            return left->AsObject() < right->AsObject();
        }
    };

    struct boomerangClasscomp {
        bool operator()(sptr<IRemoteBoomerangCallback> left, sptr<IRemoteBoomerangCallback> right) const
        {
            return left->AsObject() < right->AsObject();
        }
    };
    static constexpr int32_t argSize_ { TYPE_MAX };

    std::mutex mutex_;
    sptr<IRemoteObject::DeathRecipient> devicestatusCBDeathRecipient_ { nullptr };
    sptr<IRemoteObject::DeathRecipient> boomerangCBDeathRecipient_ { nullptr };
    std::shared_ptr<DeviceStatusMsdpClientImpl> msdpImpl_ { nullptr };
    std::map<Type, OnChangedValue> msdpData_;
    std::map<Type, std::set<const sptr<IRemoteDevStaCallback>, classcomp>> listeners_;
    std::map<std::string, std::set<const sptr<IRemoteBoomerangCallback>, boomerangClasscomp>> boomerangListeners_;
    sptr<IRemoteBoomerangCallback> notityListener_;
    sptr<IRemoteBoomerangCallback> encodeCallback_;
    int32_t type_ { -1 };
    int32_t boomerangType_ { -1 };
    int32_t event_ { -1 };
    int32_t arrs_[argSize_] {};
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DEVICESTATUS_MANAGER_H
