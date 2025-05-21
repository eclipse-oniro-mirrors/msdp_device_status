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

#ifndef I_DEVICESTATUS_H
#define I_DEVICESTATUS_H

#include <iremote_broker.h>

#include "drag_data.h"
#include "msdp_ipc_interface_code.h"
#include "iremote_dev_sta_callback.h"
#include "stationary_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class Idevicestatus : public IRemoteBroker {
public:
    virtual void Subscribe(Type type,
        ActivityEvent event,
        ReportLatencyNs latency,
        sptr<IRemoteDevStaCallback> callback) = 0;
    virtual void Unsubscribe(Type type,
        ActivityEvent event,
        sptr<IRemoteDevStaCallback> callback) = 0;
    virtual Data GetCache(const Type &type) = 0;

    virtual int32_t RegisterCoordinationListener(bool isCompatible = false) = 0;
    virtual int32_t UnregisterCoordinationListener(bool isCompatible = false) = 0;
    virtual int32_t PrepareCoordination(int32_t userData, bool isCompatible = false) = 0;
    virtual int32_t UnprepareCoordination(int32_t userData, bool isCompatible = false) = 0;
    virtual int32_t ActivateCoordination(int32_t userData, const std::string &remoteNetworkId,
        int32_t startDeviceId, bool isCompatible = false) = 0;
    virtual int32_t DeactivateCoordination(int32_t userData, bool isUnchained, bool isCompatible = false) = 0;
    virtual int32_t GetCoordinationState(int32_t userData,
        const std::string &networkId, bool isCompatible = false) = 0;
    virtual int32_t GetCoordinationState(const std::string &udId, bool &state) = 0;
    virtual int32_t StartDrag(const DragData &dragData) = 0;
    virtual int32_t StopDrag(const DragDropResult &dropResult) = 0;
    virtual int32_t UpdateDragStyle(DragCursorStyle style) = 0;
    virtual int32_t GetDragTargetPid() = 0;
    virtual int32_t GetUdKey(std::string &udKey) = 0;
    virtual int32_t AddDraglistener() = 0;
    virtual int32_t RemoveDraglistener() = 0;
    virtual int32_t AddSubscriptListener() = 0;
    virtual int32_t RemoveSubscriptListener() = 0;
    virtual int32_t AllocSocketFd(const std::string &programName, int32_t moduleType,
        int32_t &socketFd, int32_t &tokenType) = 0;
    virtual int32_t SetDragWindowVisible(bool visible, bool isForce = false) = 0;
    virtual int32_t GetShadowOffset(ShadowOffset &shadowOffset) = 0;
    virtual int32_t UpdateShadowPic(const ShadowInfo &shadowInfo) = 0;
    virtual int32_t GetDragData(DragData &dragData) = 0;
    virtual int32_t GetDragState(DragState &dragState) = 0;
    virtual int32_t GetDragSummary(std::map<std::string, int64_t> &summarys) = 0;
    virtual int32_t EnterTextEditorArea(bool enable) = 0;
    virtual int32_t GetDragAction(DragAction &dragAction) = 0;
    virtual int32_t GetExtraInfo(std::string &extraInfo) = 0;
    virtual bool IsRunning() const
    {
        return true;
    }

    virtual int32_t AddHotAreaListener() = 0;
    virtual int32_t RemoveHotAreaListener() = 0;
    virtual int32_t UpdatePreviewStyle(const PreviewStyle &previewStyle) = 0;
    virtual int32_t UpdatePreviewStyleWithAnimation(const PreviewStyle &previewStyle,
        const PreviewAnimation &animation) = 0;
    virtual int32_t AddPrivilege() = 0;
    virtual int32_t EraseMouseIcon() = 0;
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.msdp.Idevicestatus");
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // I_DEVICESTATUS_H
