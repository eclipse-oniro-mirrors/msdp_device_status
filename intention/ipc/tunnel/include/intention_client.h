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

// Implementation of client side of IPC.

#ifndef INTENTION_CLIENT_H
#define INTENTION_CLIENT_H

#include <memory>

#include "iintention.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class IntentionClient final : public std::enable_shared_from_this<IntentionClient> {
public:
    IntentionClient() = default;
    ~IntentionClient();
    DISALLOW_COPY_AND_MOVE(IntentionClient);
    static IntentionClient *GetInstance();
    // Socket
    ErrCode Socket(const std::string& programName, int32_t moduleType, int& socketFd, int32_t& tokenType);

    // Cooperate
    int32_t EnableCooperate(int32_t userData);
    int32_t DisableCooperate(int32_t userData);
    int32_t StartCooperate(const std::string& remoteNetworkId, int32_t userData, int32_t startDeviceId,
        bool checkPermission);
    int32_t StartCooperateWithOptions(const std::string &remoteNetworkId,
        int32_t userData, int32_t startDeviceId, bool checkPermission, const CooperateOptions &options);
    int32_t StopCooperate(int32_t userData, bool isUnchained, bool checkPermission);
    int32_t RegisterCooperateListener();
    int32_t UnregisterCooperateListener();
    int32_t RegisterHotAreaListener(int32_t userData, bool checkPermission);
    int32_t UnregisterHotAreaListener(int32_t userData, bool checkPermission);
    int32_t RegisterMouseEventListener(const std::string& networkId);
    int32_t UnregisterMouseEventListener(const std::string& networkId);
    int32_t GetCooperateStateSync(const std::string& udid, bool& state);
    int32_t GetCooperateStateAsync(const std::string& networkId, int32_t userData, bool isCheckPermission);
    int32_t SetDamplingCoefficient(uint32_t direction, double coefficient);

    // Drag
    int32_t StartDrag(const DragData &dragData);
    int32_t StopDrag(const DragDropResult &dropResult);
    int32_t EnableInternalDropAnimation(const std::string &animationInfo);
    int32_t AddDraglistener(bool isJsCaller);
    int32_t RemoveDraglistener(bool isJsCaller);
    int32_t AddSubscriptListener();
    int32_t RemoveSubscriptListener();
    int32_t SetDragWindowVisible(bool visible, bool isForce,
        const std::shared_ptr<Rosen::RSTransaction>& rsTransaction);
    int32_t UpdateDragStyle(DragCursorStyle style, int32_t eventId);
    int32_t UpdateShadowPic(const ShadowInfo &shadowInfo);
    int32_t GetDragTargetPid(int32_t &targetPid);
    int32_t GetUdKey(std::string &udKey);
    int32_t GetShadowOffset(ShadowOffset &shadowOffset);
    int32_t GetDragData(DragData &dragData);
    int32_t UpdatePreviewStyle(const PreviewStyle &previewStyle);
	int32_t UpdatePreviewStyleWithAnimation(const PreviewStyle &previewStyle, const PreviewAnimation &animation);
    int32_t RotateDragWindowSync(const std::shared_ptr<Rosen::RSTransaction>& rsTransaction);
    int32_t SetDragWindowScreenId(uint64_t displayId, uint64_t screenId);
    int32_t GetDragSummary(std::map<std::string, int64_t> &summarys, bool isJsCaller);
    int32_t SetDragSwitchState(bool enable, bool isJsCaller);
    int32_t SetAppDragSwitchState(bool enable, const std::string &pkgName, bool isJsCaller);
    int32_t GetDragState(DragState &dragState);
    int32_t EnableUpperCenterMode(bool enable);
    int32_t GetDragAction(DragAction &dragAction);
    int32_t GetExtraInfo(std::string &extraInfo);
    int32_t AddPrivilege();
    int32_t EraseMouseIcon();
    int32_t SetMouseDragMonitorState(bool state);
    int32_t SetDraggableState(bool state);
    int32_t GetAppDragSwitchState(bool &state);
    int32_t SetDraggableStateAsync(bool state, int64_t downTime);
    int32_t GetDragBundleInfo(DragBundleInfo &dragBundleInfo);

    // Boomerang
    int32_t SubscribeCallback(int32_t type, const std::string& bundleName,
        const sptr<IRemoteBoomerangCallback>& subCallback);
    int32_t UnsubscribeCallback(int32_t type, const std::string& bundleName,
        const sptr<IRemoteBoomerangCallback>& unsubCallback);
    int32_t NotifyMetadataBindingEvent(const std::string& bundleName,
        const sptr<IRemoteBoomerangCallback>& notifyCallback);
    int32_t SubmitMetadata(const std::string& metadata);
    int32_t BoomerangEncodeImage(const std::shared_ptr<PixelMap>& pixelMap, const std::string& metadata,
        const sptr<IRemoteBoomerangCallback>& encodeCallback);
    int32_t BoomerangDecodeImage(const std::shared_ptr<PixelMap>& pixelMap,
        const sptr<IRemoteBoomerangCallback>& decodeCallback);

    // Stationary
    int32_t SubscribeStationaryCallback(int32_t type, int32_t event,
        int32_t latency, const sptr<IRemoteDevStaCallback> &subCallback);
    int32_t UnsubscribeStationaryCallback(int32_t type, int32_t event,
        const sptr<IRemoteDevStaCallback> &unsubCallback);
    int32_t GetDeviceStatusData(int32_t type, int32_t &replyType, int32_t &replyValue);
    int32_t GetDevicePostureDataSync(DevicePostureData &postureData);

private:
    class DeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        DeathRecipient(std::shared_ptr<IntentionClient> parent);
        ~DeathRecipient() = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote);

    private:
        std::weak_ptr<IntentionClient> parent_;
    };

    ErrCode Connect();
    void ResetProxy(const wptr<IRemoteObject> &remote);

private:
    std::mutex mutex_;
    sptr<IIntention> devicestatusProxy_ { nullptr };
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ { nullptr };
    static std::shared_ptr<IntentionClient> instance_;
};

#define INTENTION_CLIENT OHOS::Msdp::DeviceStatus::IntentionClient::GetInstance()
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // INTENTION_CLIENT_H