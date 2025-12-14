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

#include "intention_service_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <thread>

#include "intention_service.h"

#undef LOG_TAG
#define LOG_TAG "IntentionServiceFuzzTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
using namespace OHOS;
using namespace OHOS::Msdp;

constexpr int32_t LISTSIZE = 25;
const std::u16string INTENTION_INTERFACE_TOKEN = u"OHOS.Msdp.IIntention";

const std::vector<IIntentionIpcCode > CODE_LIST = {
    IIntentionIpcCode::COMMAND_SOCKET,
    IIntentionIpcCode::COMMAND_ENABLE_COOPERATE,
    IIntentionIpcCode::COMMAND_DISABLE_COOPERATE,
    IIntentionIpcCode::COMMAND_START_COOPERATE,
    IIntentionIpcCode::COMMAND_STOP_COOPERATE,
    IIntentionIpcCode::COMMAND_REGISTER_COOPERATE_LISTENER,
    IIntentionIpcCode::COMMAND_UNREGISTER_COOPERATE_LISTENER,
    IIntentionIpcCode::COMMAND_REGISTER_HOT_AREA_LISTENER,
    IIntentionIpcCode::COMMAND_UNREGISTER_HOT_AREA_LISTENER,
    IIntentionIpcCode::COMMAND_REGISTER_MOUSE_EVENT_LISTENER,
    IIntentionIpcCode::COMMAND_UNREGISTER_MOUSE_EVENT_LISTENER,
    IIntentionIpcCode::COMMAND_GET_COOPERATE_STATE_SYNC,
    IIntentionIpcCode::COMMAND_GET_COOPERATE_STATE_ASYNC,
    IIntentionIpcCode::COMMAND_SET_DAMPLING_COEFFICIENT,
    IIntentionIpcCode::COMMAND_START_DRAG,
    IIntentionIpcCode::COMMAND_STOP_DRAG,
    IIntentionIpcCode::COMMAND_ADD_DRAGLISTENER,
    IIntentionIpcCode::COMMAND_REMOVE_DRAGLISTENER,
    IIntentionIpcCode::COMMAND_ADD_SUBSCRIPT_LISTENER,
    IIntentionIpcCode::COMMAND_REMOVE_SUBSCRIPT_LISTENER,
    IIntentionIpcCode::COMMAND_SET_DRAG_WINDOW_VISIBLE,
    IIntentionIpcCode::COMMAND_UPDATE_DRAG_STYLE,
    IIntentionIpcCode::COMMAND_UPDATE_SHADOW_PIC,
    IIntentionIpcCode::COMMAND_GET_DRAG_TARGET_PID,
    IIntentionIpcCode::COMMAND_GET_UD_KEY,
    IIntentionIpcCode::COMMAND_GET_SHADOW_OFFSET,
    IIntentionIpcCode::COMMAND_GET_DRAG_DATA,
    IIntentionIpcCode::COMMAND_UPDATE_PREVIEW_STYLE,
    IIntentionIpcCode::COMMAND_UPDATE_PREVIEW_STYLE_WITH_ANIMATION,
    IIntentionIpcCode::COMMAND_ROTATE_DRAG_WINDOW_SYNC,
    IIntentionIpcCode::COMMAND_SET_DRAG_WINDOW_SCREEN_ID,
    IIntentionIpcCode::COMMAND_GET_DRAG_SUMMARY,
    IIntentionIpcCode::COMMAND_SET_DRAG_SWITCH_STATE,
    IIntentionIpcCode::COMMAND_SET_APP_DRAG_SWITCH_STATE,
    IIntentionIpcCode::COMMAND_GET_DRAG_STATE,
    IIntentionIpcCode::COMMAND_ENABLE_UPPER_CENTER_MODE,
    IIntentionIpcCode::COMMAND_GET_DRAG_ACTION,
    IIntentionIpcCode::COMMAND_GET_EXTRA_INFO,
    IIntentionIpcCode::COMMAND_ADD_PRIVILEGE,
    IIntentionIpcCode::COMMAND_ERASE_MOUSE_ICON,
    IIntentionIpcCode::COMMAND_SET_MOUSE_DRAG_MONITOR_STATE,
    IIntentionIpcCode::COMMAND_SET_DRAGGABLE_STATE,
    IIntentionIpcCode::COMMAND_GET_APP_DRAG_SWITCH_STATE,
    IIntentionIpcCode::COMMAND_SET_DRAGGABLE_STATE_ASYNC,
    IIntentionIpcCode::COMMAND_GET_DRAG_BUNDLE_INFO,
    IIntentionIpcCode::COMMAND_SUBSCRIBE_CALLBACK,
    IIntentionIpcCode::COMMAND_UNSUBSCRIBE_CALLBACK,
    IIntentionIpcCode::COMMAND_NOTIFY_METADATA_BINDING_EVENT,
    IIntentionIpcCode::COMMAND_SUBMIT_METADATA,
    IIntentionIpcCode::COMMAND_BOOMERANG_ENCODE_IMAGE,
    IIntentionIpcCode::COMMAND_BOOMERANG_DECODE_IMAGE,
    IIntentionIpcCode::COMMAND_SUBSCRIBE_STATIONARY_CALLBACK,
    IIntentionIpcCode::COMMAND_UNSUBSCRIBE_STATIONARY_CALLBACK,
    IIntentionIpcCode::COMMAND_GET_DEVICE_STATUS_DATA,
    IIntentionIpcCode::COMMAND_GET_DEVICE_POSTURE_DATA_SYNC,
    IIntentionIpcCode::COMMAND_START_COOPERATE_WITH_OPTIONS,
    IIntentionIpcCode::COMMAND_ENABLE_INTERNAL_DROP_ANIMATION,
    IIntentionIpcCode::COMMAND_IS_DRAG_START,
    IIntentionIpcCode::COMMAND_GET_PAGE_CONTENT,
    IIntentionIpcCode::COMMAND_SEND_CONTROL_EVENT,
    IIntentionIpcCode::COMMAND_REGISTER_SCREEN_EVENT_CALLBACK,
    IIntentionIpcCode::COMMAND_UNREGISTER_SCREEN_EVENT_CALLBACK,
    IIntentionIpcCode::COMMAND_IS_PARALLEL_FEATURE_ENABLED,
    IIntentionIpcCode::COMMAND_LISTEN_LIVE_BROADCAST,
    IIntentionIpcCode::COMMAND_GET_LIVE_STATUS,
    IIntentionIpcCode::COMMAND_REGISTER_AWARENESS_CALLBACK,
    IIntentionIpcCode::COMMAND_UNREGISTER_AWARENESS_CALLBACK,
    IIntentionIpcCode::COMMAND_TRIGGER,
};

class IntentionServiceMock : public IntentionStub {
public:
    ErrCode Socket(const std::string& programName, int32_t moduleType, int& socketFd, int32_t& tokenType) override
    {
        (void)programName;
        (void)moduleType;
        (void)socketFd;
        (void)tokenType;
        return 0;
    }

    // Cooperate
    ErrCode EnableCooperate(int32_t userData) override
    {
        (void)userData;
        return 0;
    }

    ErrCode DisableCooperate(int32_t userData) override
    {
        (void)userData;
        return 0;
    }

    ErrCode StartCooperate(const std::string& remoteNetworkId, int32_t userData, int32_t startDeviceId,
        bool checkPermission) override
    {
        (void)remoteNetworkId;
        (void)userData;
        (void)startDeviceId;
        (void)checkPermission;
        return 0;
    }

    ErrCode StartCooperateWithOptions(const std::string& remoteNetworkId, int32_t userData, int32_t startDeviceId,
        bool checkPermission, const SequenceableCooperateOptions& options) override
    {
        (void)remoteNetworkId;
        (void)userData;
        (void)startDeviceId;
        (void)checkPermission;
        (void)options;
        return 0;
    }
    
    ErrCode StopCooperate(int32_t userData, bool isUnchained, bool checkPermission) override
    {
        (void)userData;
        (void)isUnchained;
        (void)checkPermission;
        return 0;
    }

    ErrCode RegisterCooperateListener() override
    {
        return 0;
    }

    ErrCode UnregisterCooperateListener() override
    {
        return 0;
    }

    ErrCode RegisterHotAreaListener(int32_t userData, bool checkPermission) override
    {
        (void)userData;
        (void)checkPermission;
        return 0;
    }

    ErrCode UnregisterHotAreaListener() override
    {
        return 0;
    }

    ErrCode RegisterMouseEventListener(const std::string& networkId) override
    {
        (void)networkId;
        return 0;
    }

    ErrCode UnregisterMouseEventListener(const std::string& networkId) override
    {
        (void)networkId;
        return 0;
    }

    ErrCode GetCooperateStateSync(const std::string& udid, bool& state) override
    {
        (void)udid;
        (void)state;
        return 0;
    }

    ErrCode GetCooperateStateAsync(const std::string& networkId, int32_t userData, bool isCheckPermission) override
    {
        (void)networkId;
        (void)userData;
        (void)isCheckPermission;
        return 0;
    }

    ErrCode SetDamplingCoefficient(uint32_t direction, double coefficient) override
    {
        (void)direction;
        (void)coefficient;
        return 0;
    }

    // Drag
    ErrCode StartDrag(const SequenceableDragData &sequenceableDragData) override
    {
        (void)sequenceableDragData;
        return 0;
    }

    ErrCode StopDrag(const SequenceableDragResult &sequenceableDragResult) override
    {
        (void)sequenceableDragResult;
        return 0;
    }

    ErrCode EnableInternalDropAnimation(const std::string &animationInfo) override
    {
        (void)animationInfo;
        return 0;
    }

    ErrCode AddDraglistener(bool isJsCaller) override
    {
        (void)isJsCaller;
        return 0;
    }

    ErrCode RemoveDraglistener(bool isJsCaller) override
    {
        (void)isJsCaller;
        return 0;
    }

    ErrCode SetDragWindowVisible(const SequenceableDragVisible &sequenceableDragVisible) override
    {
        (void)sequenceableDragVisible;
        return 0;
    }

    ErrCode AddSubscriptListener() override
    {
        return 0;
    }

    ErrCode RemoveSubscriptListener() override
    {
        return 0;
    }
        
    ErrCode UpdateDragStyle(int32_t style, int32_t eventId) override
    {
        (void)style;
        (void)eventId;
        return 0;
    }

    ErrCode UpdateShadowPic(const std::shared_ptr<PixelMap>& pixelMap, int32_t x, int32_t y) override
    {
        (void)pixelMap;
        (void)x;
        (void)y;
        return 0;
    }

    ErrCode GetDragTargetPid(int32_t &targetPid) override
    {
        (void)targetPid;
        return 0;
    }

    ErrCode GetUdKey(std::string &udKey) override
    {
        (void)udKey;
        return 0;
    }

    ErrCode GetShadowOffset(int32_t &offsetX, int32_t &offsetY, int32_t &width, int32_t &height) override
    {
        (void)offsetX;
        (void)offsetY;
        (void)width;
        (void)height;
        return 0;
    }

    ErrCode GetDragData(SequenceableDragData &sequenceableDragData) override
    {
        (void)sequenceableDragData;
        return 0;
    }

    ErrCode UpdatePreviewStyle(const SequenceablePreviewStyle &sequenceablePreviewStyle) override
    {
        (void)sequenceablePreviewStyle;
        return 0;
    }

    ErrCode UpdatePreviewStyleWithAnimation(const SequenceablePreviewAnimation &sequenceablePreviewAnimation) override
    {
        (void)sequenceablePreviewAnimation;
        return 0;
    }

    ErrCode RotateDragWindowSync(const SequenceableRotateWindow &sequenceableRotateWindow) override
    {
        (void)sequenceableRotateWindow;
        return 0;
    }

    ErrCode SetDragWindowScreenId(uint64_t displayId, uint64_t screenId) override
    {
        (void)displayId;
        (void)screenId;
        return 0;
    }

    ErrCode GetDragSummary(std::map<std::string, int64_t> &summarys, bool isJsCaller) override
    {
        (void)summarys;
        (void)isJsCaller;
        return 0;
    }

    ErrCode GetDragSummaryInfo(SequenceableDragSummaryInfo &sequenceableDragSummaryInfo) override
    {
        (void)sequenceableDragSummaryInfo;
        return 0;
    }

    ErrCode SetDragSwitchState(bool enable, bool isJsCaller) override
    {
        (void)enable;
        (void)isJsCaller;
        return 0;
    }

    ErrCode SetAppDragSwitchState(bool enable, const std::string &pkgName, bool isJsCaller) override
    {
        (void)enable;
        (void)pkgName;
        (void)isJsCaller;
        return 0;
    }

    ErrCode GetDragState(int32_t &dragState) override
    {
        (void)dragState;
        return 0;
    }

    ErrCode EnableUpperCenterMode(bool enable) override
    {
        (void)enable;
        return 0;
    }

    ErrCode GetDragAction(int32_t &dragAction) override
    {
        (void)dragAction;
        return 0;
    }

    ErrCode GetExtraInfo(std::string &extraInfo) override
    {
        (void)extraInfo;
        return 0;
    }

    ErrCode AddPrivilege() override
    {
        return 0;
    }

    ErrCode EraseMouseIcon() override
    {
        return 0;
    }

    ErrCode SetMouseDragMonitorState(bool state) override
    {
        (void)state;
        return 0;
    }

    ErrCode SetDraggableState(bool state) override
    {
        (void)state;
        return 0;
    }

    ErrCode GetAppDragSwitchState(bool &state) override
    {
        (void)state;
        return 0;
    }

    ErrCode SetDraggableStateAsync(bool state, int64_t downTime) override
    {
        (void)state;
        (void)downTime;
        return 0;
    }

    ErrCode GetDragBundleInfo(std::string &bundleName, bool &state) override
    {
        (void)bundleName;
        (void)state;
        return 0;
    }

    ErrCode IsDragStart(bool &isStart) override
    {
        (void)isStart;
        return 0;
    }

    // Boomerang
    ErrCode SubscribeCallback(int32_t type, const std::string& bundleName,
        const sptr<IRemoteBoomerangCallback>& subCallback) override
    {
        (void)type;
        (void)bundleName;
        (void)subCallback;
        return 0;
    }
        
    ErrCode UnsubscribeCallback(int32_t type, const std::string& bundleName,
        const sptr<IRemoteBoomerangCallback>& unsubCallback) override
    {
        (void)type;
        (void)bundleName;
        (void)unsubCallback;
        return 0;
    }
        
    ErrCode NotifyMetadataBindingEvent(const std::string& bundleName,
        const sptr<IRemoteBoomerangCallback>& notifyCallback) override
    {
        (void)bundleName;
        (void)notifyCallback;
        return 0;
    }
        
    ErrCode SubmitMetadata(const std::string& metadata) override
    {
        (void)metadata;
        return 0;
    }

    ErrCode BoomerangEncodeImage(const std::shared_ptr<PixelMap>& pixelMap, const std::string& metadata,
        const sptr<IRemoteBoomerangCallback>& encodeCallback) override
    {
        (void)pixelMap;
        (void)metadata;
        (void)encodeCallback;
        return 0;
    }
        
    ErrCode BoomerangDecodeImage(const std::shared_ptr<PixelMap>& pixelMap,
        const sptr<IRemoteBoomerangCallback>& decodeCallback) override
    {
        (void)pixelMap;
        (void)decodeCallback;
        return 0;
    }
        
    // Stationary
    ErrCode SubscribeStationaryCallback(int32_t type, int32_t event,
        int32_t latency, const sptr<IRemoteDevStaCallback> &subCallback) override
    {
        (void)type;
        (void)event;
        (void)latency;
        (void)subCallback;
        return 0;
    }
        
    ErrCode UnsubscribeStationaryCallback(int32_t type, int32_t event,
        const sptr<IRemoteDevStaCallback> &unsubCallback) override
    {
        (void)type;
        (void)event;
        (void)unsubCallback;
        return 0;
    }
        
    ErrCode GetDeviceStatusData(int32_t type, int32_t &replyType, int32_t &replyValue) override
    {
        (void)type;
        (void)replyType;
        (void)replyValue;
        return 0;
    }

    ErrCode GetDevicePostureDataSync(SequenceablePostureData &data) override
    {
        return 0;
    }

    // OnScreen
    ErrCode GetPageContent(const DeviceStatus::OnScreen::SequenceableContentOption &option,
        DeviceStatus::OnScreen::SequenceablePageContent &pageContent) override
    {
        (void)option;
        (void)pageContent;
        return 0;
    }

    ErrCode SendControlEvent(const DeviceStatus::OnScreen::SequenceableControlEvent &event) override
    {
        (void)event;
        return 0;
    }

    ErrCode RegisterScreenEventCallback(int32_t windowId, const std::string& event,
        const sptr<DeviceStatus::OnScreen::IRemoteOnScreenCallback>& onScreenCallback) override
    {
        (void)windowId;
        (void)event;
        (void)onScreenCallback;
        return 0;
    }

    ErrCode UnregisterScreenEventCallback(int32_t windowId, const std::string& event,
        const sptr<DeviceStatus::OnScreen::IRemoteOnScreenCallback>& onScreenCallback) override
    {
        (void)windowId;
        (void)event;
        (void)onScreenCallback;
        return 0;
    }

    ErrCode IsParallelFeatureEnabled(int32_t windowId, int32_t& outStatus) override
    {
        (void)windowId;
        (void)outStatus;
        return 0;
    }

    ErrCode ListenLiveBroadcast() override
    {
        return 0;
    }

    ErrCode GetLiveStatus() override
    {
        return 0;
    }
    
    ErrCode RegisterAwarenessCallback(const OnScreen::SequenceableOnscreenAwarenessCap& cap,
        const sptr<OnScreen::IRemoteOnScreenCallback>& onScreenCallback,
        const OnScreen::SequenceableOnscreenAwarenessOption& awarenessOption) override
    {
        (void)cap;
        (void)onScreenCallback;
        (void)awarenessOption;
        return 0;
    }

    ErrCode UnregisterAwarenessCallback(const OnScreen::SequenceableOnscreenAwarenessCap& cap,
        const sptr<OnScreen::IRemoteOnScreenCallback>& onScreenCallback) override
    {
        (void)cap;
        (void)onScreenCallback;
        return 0;
    }

    ErrCode Trigger(const OnScreen::SequenceableOnscreenAwarenessCap& cap,
        const OnScreen::SequenceableOnscreenAwarenessOption& awarenessOption,
        OnScreen::SequenceableOnscreenAwarenessInfo& info) override
    {
        (void)cap;
        (void)awarenessOption;
        (void)info;
        return 0;
    }

    // hidumper
    int32_t Dump(int32_t fd, const std::vector<std::u16string> &args) override
    {
        (void)fd;
        (void)args;
        return 0;
    }
};

static inline void DoSleep(void)
{
    uint32_t sleepMs = 10;
    std::this_thread::sleep_for(std::chrono::milliseconds(sleepMs));
}

class TestEnv {
    public:
        TestEnv()
        {
            isInited_ = false;
            stub_ = new IntentionServiceMock();
            if (stub_ == nullptr) {
                return;
            }
            isInited_ = true;
        }
    
        ~TestEnv()
        {
            isInited_ = false;
            stub_ = nullptr;
        }
    
        bool IsInited() const noexcept
        {
            return isInited_;
        }
    
        void DoRemoteRequest(IIntentionIpcCode code, MessageParcel &data)
        {
            MessageParcel reply;
            MessageOption option;
            if (stub_ != nullptr) {
                stub_->OnRemoteRequest(static_cast<uint32_t>(code), data, reply, option);
            }
        }
    
private:
    volatile bool isInited_;
    sptr<IntentionServiceMock> stub_;
};
}

bool IIntentionServerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return false;
    }
    FuzzedDataProvider provider(data, size);
    static TestEnv env;
    if (!env.IsInited()) {
        return 0;
    }
    OHOS::MessageParcel parcel;
    int32_t code = provider.ConsumeIntegralInRange<int32_t>(0, LISTSIZE);
    parcel.WriteInterfaceToken(INTENTION_INTERFACE_TOKEN);
    parcel.WriteBuffer(data, size);
    env.DoRemoteRequest(static_cast<IIntentionIpcCode>(code), parcel);
    DoSleep();
    return true;
}

bool IIntentionServerFuzzTest1(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return false;
    }
    FuzzedDataProvider provider(data, size);
    static TestEnv env1;
    if (!env1.IsInited()) {
        return 0;
    }
    OHOS::MessageParcel parcel;
    int32_t code = provider.ConsumeIntegralInRange<int32_t>(LISTSIZE, CODE_LIST.size());
    parcel.WriteInterfaceToken(INTENTION_INTERFACE_TOKEN);
    parcel.WriteBuffer(data, size);
    env1.DoRemoteRequest(static_cast<IIntentionIpcCode>(code), parcel);
    DoSleep();
    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    OHOS::Msdp::DeviceStatus::IIntentionServerFuzzTest(data, size);
    OHOS::Msdp::DeviceStatus::IIntentionServerFuzzTest1(data, size);
    return 0;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS