/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef INTENTION_SERVICE_H
#define INTENTION_SERVICE_H

#include "nocopyable.h"

#include "boomerang_dumper.h"
#include "boomerang_server.h"
#include "cooperate_server.h"
#include "drag_server.h"
#include "intention_dumper.h"
#include "intention_stub.h"
#include "i_context.h"
#include "sequenceable_drag_visible.h"
#include "socket_server.h"
#include "stationary_server.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class IntentionService final : public IntentionStub {
public:
    IntentionService(IContext *context);
    ~IntentionService() = default;
    DISALLOW_COPY_AND_MOVE(IntentionService);

    // Public
    using TaskProtoType = std::function<int32_t(void)>;

    // Socket
    ErrCode Socket(const std::string& programName, int32_t moduleType, int& socketFd, int32_t& tokenType) override;

    // Cooperate
    ErrCode EnableCooperate(int32_t userData) override;
    ErrCode DisableCooperate(int32_t userData) override;
    ErrCode StartCooperate(const std::string& remoteNetworkId, int32_t userData, int32_t startDeviceId,
        bool checkPermission) override;
    ErrCode StopCooperate(int32_t userData, bool isUnchained, bool checkPermission) override;
    ErrCode RegisterCooperateListener() override;
    ErrCode UnregisterCooperateListener() override;
    ErrCode RegisterHotAreaListener(int32_t userData, bool checkPermission) override;
    ErrCode UnregisterHotAreaListener() override;
    ErrCode RegisterMouseEventListener(const std::string& networkId) override;
    ErrCode UnregisterMouseEventListener(const std::string& networkId) override;
    ErrCode GetCooperateStateSync(const std::string& udid, bool& state) override;
    ErrCode GetCooperateStateAsync(const std::string& networkId, int32_t userData, bool isCheckPermission) override;
    ErrCode SetDamplingCoefficient(uint32_t direction, double coefficient) override;
    
    // Drag
    ErrCode StartDrag(const SequenceableDragData &sequenceableDragData) override;
    ErrCode StopDrag(const SequenceableDragResult &sequenceableDragResult) override;
    ErrCode AddDraglistener(bool isJsCaller) override;
    ErrCode RemoveDraglistener(bool isJsCaller) override;
    ErrCode SetDragWindowVisible(const SequenceableDragVisible &sequenceableDragVisible) override;
    ErrCode AddSubscriptListener() override;
    ErrCode RemoveSubscriptListener() override;
    ErrCode UpdateDragStyle(int32_t style, int32_t eventId) override;
    ErrCode UpdateShadowPic(const std::shared_ptr<PixelMap>& pixelMap, int32_t x, int32_t y) override;
    ErrCode GetDragTargetPid(int32_t &targetPid) override;
    ErrCode GetUdKey(std::string &udKey) override;
    ErrCode GetShadowOffset(int32_t &offsetX, int32_t &offsetY, int32_t &width, int32_t &height) override;
    ErrCode GetDragData(SequenceableDragData &sequenceableDragData) override;
    ErrCode UpdatePreviewStyle(const SequenceablePreviewStyle &sequenceablePreviewStyle) override;
    ErrCode UpdatePreviewStyleWithAnimation(const SequenceablePreviewAnimation &sequenceablePreviewAnimation) override;
    ErrCode RotateDragWindowSync(const SequenceableRotateWindow &sequenceableRotateWindow) override;
    ErrCode SetDragWindowScreenId(uint64_t displayId, uint64_t screenId) override;
    ErrCode GetDragSummary(std::map<std::string, int64_t> &summarys, bool isJsCaller) override;
    ErrCode SetDragSwitchState(bool enable, bool isJsCaller) override;
    ErrCode SetAppDragSwitchState(bool enable, const std::string &pkgName, bool isJsCaller) override;
    ErrCode GetDragState(int32_t &dragState) override;
    ErrCode EnableUpperCenterMode(bool enable) override;
    ErrCode GetDragAction(int32_t &dragAction) override;
    ErrCode GetExtraInfo(std::string &extraInfo) override;
    ErrCode AddPrivilege() override;
    ErrCode EraseMouseIcon() override;
    ErrCode SetMouseDragMonitorState(bool state) override;
    ErrCode SetDraggableState(bool state) override;
    ErrCode GetAppDragSwitchState(bool& state) override;
    ErrCode SetDraggableStateAsync(bool state, int64_t downTime) override;
    ErrCode GetDragBundleInfo(std::string &bundleName, bool &state) override;

    // Boomerang
    ErrCode SubscribeCallback(int32_t type, const std::string& bundleName,
        const sptr<IRemoteBoomerangCallback>& subCallback) override;
    ErrCode UnsubscribeCallback(int32_t type, const std::string& bundleName,
        const sptr<IRemoteBoomerangCallback>& unsubCallback) override;
    ErrCode NotifyMetadataBindingEvent(const std::string& bundleName,
        const sptr<IRemoteBoomerangCallback>& notifyCallback) override;
    ErrCode SubmitMetadata(const std::string& metaData) override;
    ErrCode BoomerangEncodeImage(const std::shared_ptr<PixelMap>& pixelMap, const std::string& metaData,
        const sptr<IRemoteBoomerangCallback>& encodeCallback) override;
    ErrCode BoomerangDecodeImage(const std::shared_ptr<PixelMap>& pixelMap,
        const sptr<IRemoteBoomerangCallback>& decodeCallback) override;

    // Stationary
    ErrCode SubscribeStationaryCallback(int32_t type, int32_t event,
        int32_t latency, const sptr<IRemoteDevStaCallback> &subCallback) override;
    ErrCode UnsubscribeStationaryCallback(int32_t type, int32_t event,
        const sptr<IRemoteDevStaCallback> &unsubCallback) override;
    ErrCode GetDeviceStatusData(int32_t type, int32_t &replyType, int32_t &replyValue) override;

private:
    CallingContext GetCallingContext();
    void PrintCallingContext(const CallingContext &context);
    int32_t PostSyncTask(TaskProtoType task);
private:
    IContext *context_ { nullptr };
    SocketServer socketServer_;
    StationaryServer stationary_;
    CooperateServer cooperate_;
    DragServer drag_;
    IntentionDumper dumper_;
    BoomerangServer boomerang_;
    BoomerangDumper boomerangDumper_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // INTENTION_SERVICE_H
