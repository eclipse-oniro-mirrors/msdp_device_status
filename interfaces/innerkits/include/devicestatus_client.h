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

#ifndef DEVICESTATUS_CLIENT_H
#define DEVICESTATUS_CLIENT_H

#include <functional>
#include <map>

#include <singleton.h>

#include "devicestatus_common.h"
#include "drag_data.h"
#include "i_coordination_listener.h"
#include "i_devicestatus.h"
#include "stationary_callback.h"
#include "stationary_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class DeviceStatusClient final : public DelayedRefSingleton<DeviceStatusClient> {
    DECLARE_DELAYED_REF_SINGLETON(DeviceStatusClient)

public:
    std::map<Type, int32_t> GetTypeMap()
    {
        return typeMap_;
    }
    DISALLOW_COPY_AND_MOVE(DeviceStatusClient);

    int32_t SubscribeCallback(Type type, ActivityEvent event, ReportLatencyNs latency,
        sptr<IRemoteDevStaCallback> callback);
    int32_t UnsubscribeCallback(Type type, ActivityEvent event, sptr<IRemoteDevStaCallback> callback);
    Data GetDeviceStatusData(const Type type);
    void RegisterDeathListener(std::function<void()> deathListener);
    int32_t RegisterCoordinationListener(bool isCompatible = false);
    int32_t UnregisterCoordinationListener(bool isCompatible = false);
    int32_t PrepareCoordination(int32_t userData, bool isCompatible = false);
    int32_t UnprepareCoordination(int32_t userData, bool isCompatible = false);
    int32_t ActivateCoordination(int32_t userData,
        const std::string &remoteNetworkId, int32_t startDeviceId, bool isCompatible = false);
    int32_t DeactivateCoordination(int32_t userData, bool isUnchained, bool isCompatible = false);
    int32_t GetCoordinationState(int32_t userData, const std::string &networkId, bool isCompatible = false);
    int32_t GetCoordinationState(const std::string &udId, bool &state);
    int32_t StartDrag(const DragData &dragData);
    int32_t StopDrag(const DragDropResult &dropResult);
    int32_t UpdateDragStyle(DragCursorStyle style);
    int32_t GetDragTargetPid();
    int32_t GetUdKey(std::string &udKey);
    int32_t AddDraglistener();
    int32_t RemoveDraglistener();
    int32_t AddSubscriptListener();
    int32_t RemoveSubscriptListener();
    int32_t SetDragWindowVisible(bool visible, bool isForce = false);
    int32_t GetShadowOffset(ShadowOffset &shadowOffset);
    int32_t UpdateShadowPic(const ShadowInfo &shadowInfo);
    int32_t GetDragData(DragData &dragData);
    int32_t GetDragState(DragState &dragState);
    int32_t GetDragAction(DragAction &dragAction);
    int32_t GetExtraInfo(std::string &extraInfo);
    int32_t AllocSocketPair(int32_t moduleType);
    int32_t GetClientSocketFdOfAllocedSocketPair() const;
    int32_t AddHotAreaListener();
    int32_t RemoveHotAreaListener();
    int32_t UpdatePreviewStyle(const PreviewStyle &previewStyle);
    int32_t UpdatePreviewStyleWithAnimation(const PreviewStyle &previewStyle, const PreviewAnimation &animation);
    int32_t GetDragSummary(std::map<std::string, int64_t> &summarys);
    int32_t EnterTextEditorArea(bool enable);
    int32_t AddPrivilege();
    int32_t EraseMouseIcon();
    int32_t GetDragBundleInfo(DragBundleInfo &dragBundleInfo);

private:
    class DeviceStatusDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        DeviceStatusDeathRecipient() = default;
        ~DeviceStatusDeathRecipient() = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote);

    private:
        DISALLOW_COPY_AND_MOVE(DeviceStatusDeathRecipient);
    };

    ErrCode Connect();
    void ResetProxy(const wptr<IRemoteObject> &remote);

    sptr<Idevicestatus> devicestatusProxy_ { nullptr };
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ { nullptr };
    std::mutex mutex_;
    int32_t tokenType_ { -1 };
    int32_t socketFd_ { -1 };
    std::map<Type, int32_t> typeMap_;
    std::function<void()> deathListener_ { nullptr };
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DEVICESTATUS_CLIENT_H
