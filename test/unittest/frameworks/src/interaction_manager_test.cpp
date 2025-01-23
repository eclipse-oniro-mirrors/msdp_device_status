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

#include <future>
#include <optional>
#include <utility>
#include <vector>

#include <unistd.h>

#include "accesstoken_kit.h"
#include "display_manager.h"
#include <gtest/gtest.h>
#include "input_device.h"
#include "input_manager.h"
#include "parcel.h"
#include "pointer_event.h"
#include "securec.h"

#include "coordination_message.h"
#include "devicestatus_define.h"
#include "devicestatus_errors.h"
#include "drag_data_util.h"
#include "interaction_manager.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

#undef LOG_TAG
#define LOG_TAG "InteractionManagerTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
constexpr int32_t TIME_WAIT_FOR_INJECT_MS { 80 };
constexpr int32_t TIME_WAIT_FOR_TOUCH_DOWN_MS { 1000 };
constexpr int32_t PROMISE_WAIT_SPAN_MS { 2000 };
constexpr int32_t TEST_PIXEL_MAP_WIDTH { 200 };
constexpr int32_t TEST_PIXEL_MAP_HEIGHT { 200 };
constexpr int32_t MAX_PIXEL_MAP_WIDTH { 600 };
constexpr int32_t MAX_PIXEL_MAP_HEIGHT { 600 };
constexpr int32_t MOUSE_POINTER_ID { 0 };
constexpr int32_t TOUCH_POINTER_ID { 1 };
constexpr int32_t MOUSE_POINTER_ID_INJECT { 10000 };
constexpr int32_t TOUCH_POINTER_ID_INJECT { 20001 };
constexpr int32_t DISPLAY_ID { 0 };
constexpr int32_t DRAG_SRC_X { 0 };
constexpr int32_t DRAG_SRC_Y { 0 };
constexpr int32_t DRAG_DST_X { 500 };
constexpr int32_t DRAG_DST_Y { 500 };
constexpr int32_t DRAG_NUM { 1 };
constexpr int32_t INT32_BYTE { 4 };
constexpr int32_t SUBSTR_UDKEY_LEN { 6 };
constexpr int32_t WINDOW_ID { -1 };
constexpr int32_t HOT_AREA_COOR { 220 };
constexpr int32_t HOT_AREA_STEP { 150 };
constexpr int32_t HOT_AREA_SPAN { 70 };
constexpr uint32_t RECIVE_LOOP_COUNT { 5 };
constexpr uint32_t DEFAULT_ICON_COLOR { 0xFF };
constexpr bool HAS_CANCELED_ANIMATION { true };
constexpr bool HAS_CUSTOM_ANIMATION { true };
constexpr int32_t MOVE_STEP { 10 };
constexpr int32_t FOREGROUND_COLOR_IN { 0x33FF0000 };
constexpr int32_t FOREGROUND_COLOR_OUT { 0x00000000 };
constexpr int32_t ANIMATION_DURATION { 500 };
constexpr int32_t SRC_MAIN_WINDOW { 0 };
constexpr int32_t TARGET_MAIN_WINDOW { 0 };
constexpr int64_t DOWN_TIME { 1 };
const std::string UD_KEY { "Unified data key" };
const std::string SYSTEM_CORE { "system_core" };
const std::string SYSTEM_BASIC { "system_basic" };
const std::string CURVE_NAME { "cubic-bezier" };
const std::string EXTRA_INFO { "{ \"drag_corner_radius\": 20, \"drag_allow_distributed\": false }" };
const std::string FILTER_INFO { "{ \"dip_scale\": 3.5 }" };
int32_t g_deviceMouseId { -1 };
int32_t g_deviceTouchId { -1 };
int32_t g_screenWidth { 720 };
int32_t g_screenHeight { 1280 };
uint64_t g_tokenID { 0 };
const char* g_cores[] = { "ohos.permission.INPUT_MONITORING" };
const char* g_basics[] = { "ohos.permission.COOPERATE_MANAGER" };
const char* g_coresInject[] = { "ohos.permission.INJECT_INPUT_EVENT" };
std::shared_ptr<MMI::KeyEvent> g_keyEvent = MMI::KeyEvent::Create();
} // namespace

class InteractionManagerTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase();
    static std::vector<int32_t> GetInputDeviceIds();
    static std::shared_ptr<MMI::InputDevice> GetDevice(int32_t deviceId);
    static std::pair<int32_t, int32_t> GetMouseAndTouch();
    static std::shared_ptr<Media::PixelMap> CreatePixelMap(int32_t width, int32_t height);
    static std::optional<DragData> CreateDragData(const std::pair<int32_t, int32_t> &pixelMapSize, int32_t sourceType,
        int32_t pointerId, int32_t displayId, const std::pair<int32_t, int32_t> &location);
    static MMI::PointerEvent::PointerItem CreatePointerItem(int32_t pointerId,
        int32_t deviceId, const std::pair<int32_t, int32_t> &displayLocation, bool isPressed);
    static std::shared_ptr<MMI::PointerEvent> SetupPointerEvent(const std::pair<int32_t, int32_t> &displayLocation,
        int32_t action, int32_t sourceType, int32_t pointerId, bool isPressed);
    static void SimulateDownPointerEvent(
        const std::pair<int32_t, int32_t> &location, int32_t sourceType, int32_t pointerId);
    static void SimulateUpPointerEvent(
        const std::pair<int32_t, int32_t> &location, int32_t sourceType, int32_t pointerId);
    static void SimulateMovePointerEvent(const std::pair<int32_t, int32_t> &srcLocation,
        const std::pair<int32_t, int32_t> &dstLocation, int32_t sourceType, int32_t pointerId, bool isPressed);
    static int32_t TestAddMonitor(std::shared_ptr<MMI::IInputEventConsumer> consumer);
    static void TestRemoveMonitor(int32_t monitorId);
    static void PrintDragData(const DragData &dragData);
    static void SetPermission(const std::string &level, const char** perms, size_t permAmount);
    static void RemovePermission();
    static void SetupKeyEvent(int32_t action, int32_t key, bool isPressed);
    static void ClearUpKeyEvent();
    static void SimulateDownKeyEvent(int32_t key);
    static void SimulateUpKeyEvent(int32_t key);
    static void PrintDragAction(DragAction dragAction);
    static void AssignToAnimation(PreviewAnimation &animation);
    static void EnableCooperate();
};

void InteractionManagerTest::SetPermission(const std::string &level, const char** perms, size_t permAmount)
{
    CALL_DEBUG_ENTER;
    if (perms == nullptr || permAmount == 0) {
        FI_HILOGE("The perms is empty");
        return;
    }

    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = permAmount,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "InteractionManagerTest",
        .aplStr = level.c_str(),
    };
    g_tokenID = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(g_tokenID);
    OHOS::Security::AccessToken::AccessTokenKit::AccessTokenKit::ReloadNativeTokenInfo();
}

void InteractionManagerTest::RemovePermission()
{
    CALL_DEBUG_ENTER;
    int32_t ret = OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenID);
    if (ret != RET_OK) {
        FI_HILOGE("Failed to remove permission");
        return;
    }
}

class DragListenerTest : public IDragListener {
public:
    DragListenerTest() {}
    explicit DragListenerTest(const std::string& name) : moduleName_(name) {}
    void OnDragMessage(DragState state) override
    {
        if (moduleName_.empty()) {
            moduleName_ = std::string("DragListenerTest");
        }
        FI_HILOGD("%{public}s, state:%{public}s", moduleName_.c_str(), PrintDragMessage(state).c_str());
    }
private:
    std::string PrintDragMessage(DragState state)
    {
        std::string type = "unknow";
        const std::map<DragState, std::string> stateType = {
            { DragState::ERROR, "error"},
            { DragState::START, "start"},
            { DragState::STOP, "stop"},
            { DragState::CANCEL, "cancel"}
        };
        auto item = stateType.find(state);
        if (item != stateType.end()) {
            type = item->second;
        }
        return type;
    }
private:
    std::string moduleName_;
};

class SubscriptListenerTest : public ISubscriptListener {
public:
    SubscriptListenerTest() {}
    explicit SubscriptListenerTest(const std::string& name) : moduleName_(name) {}
    void OnMessage(DragCursorStyle style) override
    {
        SetDragSyle(style);
        if (moduleName_.empty()) {
            moduleName_ = std::string("SubscriptListenerTest");
        }
        FI_HILOGD("Received notification event for subscriptListener, %{public}s, state:%{public}s",
            moduleName_.c_str(), PrintStyleMessage(style).c_str());
    }

    DragCursorStyle GetDragStyle()
    {
        return dragStyle_;
    }

private:
    void SetDragSyle(DragCursorStyle style)
    {
        dragStyle_ = style;
    }

    std::string PrintStyleMessage(DragCursorStyle style)
    {
        std::string type = "unknow";
        const std::map<DragCursorStyle, std::string> cursorStyles = {
            { DragCursorStyle::DEFAULT, "default"},
            { DragCursorStyle::FORBIDDEN, "forbidden"},
            { DragCursorStyle::COPY, "copy"},
            { DragCursorStyle::MOVE, "move"}
        };
        auto item = cursorStyles.find(style);
        if (item != cursorStyles.end()) {
            type = item->second;
        }
        return type;
    }

private:
    DragCursorStyle dragStyle_ { DragCursorStyle::DEFAULT };
    std::string moduleName_;
};

class UnitTestStartDragListener : public IStartDragListener {
public:
    explicit UnitTestStartDragListener(std::function<void(const DragNotifyMsg&)> function) : function_(function) { }
    void OnDragEndMessage(const DragNotifyMsg &msg) override
    {
        FI_HILOGD("DisplayX:%{public}d, displayY:%{public}d, targetPid:%{public}d, result:%{public}d",
            msg.displayX, msg.displayY, msg.targetPid, static_cast<int32_t>(msg.result));
        if (function_ != nullptr) {
            function_(msg);
        }
        FI_HILOGD("Unit test OnDragEndMessage");
    }

    void OnHideIconMessage() override
    {
        FI_HILOGI("Unit test OnHideIconMessage");
    }
private:
    std::function<void(const DragNotifyMsg&)> function_;
};

std::vector<int32_t> InteractionManagerTest::GetInputDeviceIds()
{
    std::vector<int32_t> realDeviceIds;
    auto callback = [&realDeviceIds](std::vector<int32_t>& deviceIds) {
        realDeviceIds = deviceIds;
    };
    int32_t ret = MMI::InputManager::GetInstance()->GetDeviceIds(callback);
    if (ret != RET_OK) {
        FI_HILOGE("Get device ids failed");
        return {};
    }
    return realDeviceIds;
}

std::shared_ptr<MMI::InputDevice> InteractionManagerTest::GetDevice(int32_t deviceId)
{
    std::shared_ptr<MMI::InputDevice> inputDevice;
    auto callback = [&inputDevice](std::shared_ptr<MMI::InputDevice> device) {
        inputDevice = device;
    };
    int32_t ret = MMI::InputManager::GetInstance()->GetDevice(deviceId, callback);
    if (ret != RET_OK || inputDevice == nullptr) {
        FI_HILOGE("Get device failed");
        return nullptr;
    }
    return inputDevice;
}

std::pair<int32_t, int32_t> InteractionManagerTest::GetMouseAndTouch()
{
    std::vector<int32_t> deviceIds = GetInputDeviceIds();
    std::pair<int32_t, int32_t> mouseAndTouch { -1, -1 };
    for (const auto& id : deviceIds) {
        std::shared_ptr<MMI::InputDevice> device = GetDevice(id);
        CHKPC(device);
        if (device->HasCapability(MMI::InputDeviceCapability::INPUT_DEV_CAP_POINTER)) {
            mouseAndTouch.first = device->GetId();
        }
        if (device->HasCapability(MMI::InputDeviceCapability::INPUT_DEV_CAP_TOUCH)) {
            mouseAndTouch.second = device->GetId();
        }
    }
    return mouseAndTouch;
}

void InteractionManagerTest::SetUpTestCase()
{
    auto mouseAndTouch = GetMouseAndTouch();
    g_deviceMouseId = mouseAndTouch.first;
    g_deviceTouchId = mouseAndTouch.second;
}

void InteractionManagerTest::SetUp()
{
    EnableCooperate();
}

void InteractionManagerTest::TearDown()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

void InteractionManagerTest::EnableCooperate()
{
    SetPermission(SYSTEM_BASIC, g_basics, sizeof(g_basics) / sizeof(g_basics[0]));
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto fun = [&promiseFlag](const std::string &listener, const CoordinationMsgInfo &coordinationMessages) {
        FI_HILOGD("Prepare coordination success, listener:%{public}s", listener.c_str());
        promiseFlag.set_value(true);
    };
    bool isCompatible = true;
    int32_t ret = InteractionManager::GetInstance()->PrepareCoordination(fun, isCompatible);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    if (ret == RET_OK) {
        FI_HILOGI("PrepareCoordination successfully");
    } else {
        FI_HILOGE("PrepareCoordination failed");
    }
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) != std::future_status::timeout);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COORDINATION
    RemovePermission();
}

std::shared_ptr<Media::PixelMap> InteractionManagerTest::CreatePixelMap(int32_t width, int32_t height)
{
    CALL_DEBUG_ENTER;
    OHOS::Media::InitializationOptions opts;
    opts.size.width = width;
    opts.size.height = height;
    opts.pixelFormat = Media::PixelFormat::BGRA_8888;
    opts.alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.scaleMode = Media::ScaleMode::FIT_TARGET_SIZE;

    int32_t colorLen = width * height;
    uint32_t* colors = new (std::nothrow) uint32_t[colorLen];
    CHKPP(colors);
    int32_t colorByteCount = colorLen * INT32_BYTE;
    if (memset_s(colors, colorByteCount, DEFAULT_ICON_COLOR, colorByteCount) != EOK) {
        delete[] colors;
        FI_HILOGE("memset_s failed");
        return nullptr;
    }
    std::shared_ptr<Media::PixelMap> pixelMap = Media::PixelMap::Create(colors, colorLen, opts);
    if (pixelMap == nullptr) {
        delete[] colors;
        FI_HILOGE("Create pixelMap failed");
        return nullptr;
    }
    delete[] colors;
    return pixelMap;
}

std::optional<DragData> InteractionManagerTest::CreateDragData(const std::pair<int32_t, int32_t> &pixelMapSize,
    int32_t sourceType, int32_t pointerId, int32_t displayId, const std::pair<int32_t, int32_t> &location)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<Media::PixelMap> pixelMap = CreatePixelMap(pixelMapSize.first, pixelMapSize.second);
    if (pixelMap == nullptr) {
        FI_HILOGE("Create pixelmap failed");
        return std::nullopt;
    }
    ShadowInfo shadowInfo { pixelMap, 0, 0 };
    DragData dragData;
    dragData.shadowInfos.push_back(shadowInfo);
    dragData.buffer = std::vector<uint8_t>(MAX_BUFFER_SIZE, 0);
    dragData.udKey = UD_KEY;
    dragData.sourceType = sourceType;
    dragData.pointerId = pointerId;
    dragData.dragNum = DRAG_NUM;
    dragData.displayX = location.first;
    dragData.displayY = location.second;
    dragData.displayId = displayId;
    dragData.hasCanceledAnimation = HAS_CANCELED_ANIMATION;
    dragData.extraInfo = EXTRA_INFO;
    dragData.filterInfo = FILTER_INFO;
    dragData.mainWindow = SRC_MAIN_WINDOW;
    return dragData;
}

MMI::PointerEvent::PointerItem InteractionManagerTest::CreatePointerItem(int32_t pointerId, int32_t deviceId,
    const std::pair<int32_t, int32_t> &displayLocation, bool isPressed)
{
    MMI::PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    item.SetDeviceId(deviceId);
    item.SetDisplayX(displayLocation.first);
    item.SetDisplayY(displayLocation.second);
    item.SetPressed(isPressed);
    return item;
}

std::shared_ptr<MMI::PointerEvent> InteractionManagerTest::SetupPointerEvent(const std::pair<int32_t, int32_t>
    &displayLocation, int32_t action, int32_t sourceType, int32_t pointerId, bool isPressed)
{
    CALL_DEBUG_ENTER;
    auto pointerEvent = MMI::PointerEvent::Create();
    CHKPP(pointerEvent);
    pointerEvent->SetPointerAction(action);
    pointerEvent->SetSourceType(sourceType);
    pointerEvent->SetPointerId(pointerId);
    MMI::PointerEvent::PointerItem curPointerItem;
    if (sourceType == MMI::PointerEvent::SOURCE_TYPE_MOUSE) {
        curPointerItem = CreatePointerItem(pointerId, g_deviceMouseId, displayLocation, isPressed);
    } else if (sourceType == MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        curPointerItem = CreatePointerItem(pointerId, g_deviceTouchId, displayLocation, isPressed);
    } else {
        FI_HILOGE("Unknow sourceType:%{public}d", sourceType);
        return nullptr;
    }
    pointerEvent->AddPointerItem(curPointerItem);
    return pointerEvent;
}

void InteractionManagerTest::SimulateDownPointerEvent(const std::pair<int32_t, int32_t> &location, int32_t sourceType,
    int32_t pointerId)
{
    CALL_DEBUG_ENTER;
    SetPermission(SYSTEM_CORE, g_coresInject, sizeof(g_coresInject) / sizeof(g_coresInject[0]));
    std::shared_ptr<MMI::PointerEvent> pointerEvent =
        SetupPointerEvent(location, MMI::PointerEvent::POINTER_ACTION_DOWN, sourceType, pointerId, true);
    CHKPV(pointerEvent);
    FI_HILOGD("TEST:sourceType:%{public}d, pointerId:%{public}d, pointerAction:%{public}d",
        pointerEvent->GetSourceType(), pointerEvent->GetPointerId(), pointerEvent->GetPointerAction());
    MMI::InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    RemovePermission();
}

void InteractionManagerTest::SimulateUpPointerEvent(const std::pair<int32_t, int32_t> &location, int32_t sourceType,
    int32_t pointerId)
{
    CALL_DEBUG_ENTER;
    SetPermission(SYSTEM_CORE, g_coresInject, sizeof(g_coresInject) / sizeof(g_coresInject[0]));
    std::shared_ptr<MMI::PointerEvent> pointerEvent = SetupPointerEvent(location,
        MMI::PointerEvent::POINTER_ACTION_UP, sourceType, pointerId, false);
    CHKPV(pointerEvent);
    FI_HILOGD("TEST:sourceType:%{public}d, pointerId:%{public}d, pointerAction:%{public}d",
        pointerEvent->GetSourceType(), pointerEvent->GetPointerId(), pointerEvent->GetPointerAction());
    MMI::InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    RemovePermission();
}

void InteractionManagerTest::SimulateMovePointerEvent(const std::pair<int32_t, int32_t> &srcLocation,
    const std::pair<int32_t, int32_t> &dstLocation, int32_t sourceType, int32_t pointerId, bool isPressed)
{
    CALL_DEBUG_ENTER;
    SetPermission(SYSTEM_CORE, g_coresInject, sizeof(g_coresInject) / sizeof(g_coresInject[0]));
    int32_t srcX = srcLocation.first;
    int32_t srcY = srcLocation.second;
    int32_t dstX = dstLocation.first;
    int32_t dstY = dstLocation.second;
    std::vector<std::pair<int32_t, int32_t>> coordinates;
    if (dstX == srcX) {
        for (int32_t y = srcY; y <= dstY; y += MOVE_STEP) {
            coordinates.push_back({srcX, y});
        }
        for (int32_t y = srcY; y > dstY; y -= MOVE_STEP) {
            coordinates.push_back({srcX, y});
        }
    } else {
        double ratio = (dstY - srcY) * 1.0 / (dstX - srcX);
        for (int32_t x = srcX; x < dstX; x += MOVE_STEP) {
            coordinates.push_back({x, srcY + static_cast<int32_t>(ratio * (x - srcX))});
        }
        for (int32_t x = srcX; x >= dstX; x -= MOVE_STEP) {
            coordinates.push_back({x, srcY + static_cast<int32_t>(ratio * (x - srcX))});
        }
        coordinates.push_back({dstX, dstY});
    }
    for (const auto& pointer : coordinates) {
        std::shared_ptr<MMI::PointerEvent> pointerEvent =
            SetupPointerEvent(pointer, MMI::PointerEvent::POINTER_ACTION_MOVE, sourceType, pointerId, isPressed);
        CHKPC(pointerEvent);
        FI_HILOGD("TEST:sourceType:%{public}d, pointerId:%{public}d, pointerAction:%{public}d",
            pointerEvent->GetSourceType(), pointerEvent->GetPointerId(), pointerEvent->GetPointerAction());
        MMI::InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_INJECT_MS));
    }
    RemovePermission();
}

int32_t InteractionManagerTest::TestAddMonitor(std::shared_ptr<MMI::IInputEventConsumer> consumer)
{
    CHKPR(consumer, RET_ERR);
    return MMI::InputManager::GetInstance()->AddMonitor(consumer);
}

void InteractionManagerTest::TestRemoveMonitor(int32_t monitorId)
{
    MMI::InputManager::GetInstance()->RemoveMonitor(monitorId);
}

void InteractionManagerTest::PrintDragData(const DragData &dragData)
{
    CALL_DEBUG_ENTER;
    for (const auto &shadowInfo : dragData.shadowInfos) {
        CHKPV(shadowInfo.pixelMap);
        FI_HILOGD("PixelFormat:%{public}d, PixelAlphaType:%{public}d, PixelAllocatorType:%{public}d,"
            " PixelWidth:%{public}d, PixelHeight:%{public}d, shadowX:%{public}d, shadowY:%{public}d",
            static_cast<int32_t>(shadowInfo.pixelMap->GetPixelFormat()),
            static_cast<int32_t>(shadowInfo.pixelMap->GetAlphaType()),
            static_cast<int32_t>(shadowInfo.pixelMap->GetAllocatorType()),
            shadowInfo.pixelMap->GetWidth(), shadowInfo.pixelMap->GetHeight(), shadowInfo.x, shadowInfo.y);
    }
    FI_HILOGD("SourceType:%{public}d, pointerId:%{public}d, displayId:%{public}d, displayX:%{public}d,"
        " displayY:%{public}d, dragNum:%{public}d, hasCanceledAnimation:%{public}d, udKey:%{public}s",
        dragData.sourceType, dragData.pointerId, dragData.displayId, dragData.displayX, dragData.displayY,
        dragData.dragNum, dragData.hasCanceledAnimation, dragData.udKey.substr(0, SUBSTR_UDKEY_LEN).c_str());
}

void InteractionManagerTest::SetupKeyEvent(
    int32_t action, int32_t key, bool isPressed)
{
    CALL_DEBUG_ENTER;
    CHKPV(g_keyEvent);
    MMI::KeyEvent::KeyItem keyItem;
    keyItem.SetKeyCode(key);
    keyItem.SetDeviceId(1);
    keyItem.SetDownTime(DOWN_TIME);
    g_keyEvent->SetKeyAction(action);
    g_keyEvent->SetKeyCode(key);
    if (action == MMI::KeyEvent::KEY_ACTION_DOWN) {
        keyItem.SetPressed(isPressed);
    } else if (action == MMI::KeyEvent::KEY_ACTION_UP) {
        g_keyEvent->RemoveReleasedKeyItems(keyItem);
    }
    g_keyEvent->AddPressedKeyItems(keyItem);
}

void InteractionManagerTest::ClearUpKeyEvent()
{
    CALL_DEBUG_ENTER;
    CHKPV(g_keyEvent);
    for (const auto& iter : g_keyEvent->GetKeyItems()) {
        if (!iter.IsPressed()) {
            FI_HILOGD("TEST:Clean keyItem, keyCode:%{public}d", iter.GetKeyCode());
            g_keyEvent->RemoveReleasedKeyItems(iter);
            return;
        }
    }
}

void InteractionManagerTest::SimulateDownKeyEvent(int32_t key)
{
    CALL_DEBUG_ENTER;
    SetPermission(SYSTEM_CORE, g_coresInject, sizeof(g_coresInject) / sizeof(g_coresInject[0]));
    SetupKeyEvent(MMI::KeyEvent::KEY_ACTION_DOWN, key, true);
    FI_HILOGD("TEST:keyCode:%{public}d, keyAction: KEY_ACTION_DOWN", key);
    MMI::InputManager::GetInstance()->SimulateInputEvent(g_keyEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_INJECT_MS));
    RemovePermission();
}

void InteractionManagerTest::SimulateUpKeyEvent(int32_t key)
{
    CALL_DEBUG_ENTER;
    SetPermission(SYSTEM_CORE, g_coresInject, sizeof(g_coresInject) / sizeof(g_coresInject[0]));
    SetupKeyEvent(MMI::KeyEvent::KEY_ACTION_UP, key, false);
    FI_HILOGD("TEST:keyCode:%{public}d, keyAction: KEY_ACTION_UP", key);
    MMI::InputManager::GetInstance()->SimulateInputEvent(g_keyEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_INJECT_MS));
    RemovePermission();
}

void InteractionManagerTest::PrintDragAction(DragAction dragAction)
{
    switch (dragAction) {
        case DragAction::MOVE:{
            FI_HILOGD("drag action: MOVE");
            break;
        }
        case DragAction::COPY:{
            FI_HILOGD("drag action: COPY");
            break;
        }
        default:{
            FI_HILOGD("drag action: UNKNOWN");
            break;
        }
    }
}

void InteractionManagerTest::AssignToAnimation(PreviewAnimation &animation)
{
    animation.duration = ANIMATION_DURATION;
    animation.curveName = CURVE_NAME;
    animation.curve = { 0.33, 0, 0.67, 1 };
}

class InputEventCallbackTest : public MMI::IInputEventConsumer {
public:
    InputEventCallbackTest() {}
    explicit InputEventCallbackTest(std::function<void()> callback) : callback_(callback) {}
    void OnInputEvent(std::shared_ptr<MMI::KeyEvent> keyEvent) const override {};
    void OnInputEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent) const override;
    void OnInputEvent(std::shared_ptr<MMI::AxisEvent> axisEvent) const override {};
private:
    std::function<void()> callback_ { nullptr };
};

void InputEventCallbackTest::OnInputEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent) const
{
    CALL_DEBUG_ENTER;
    ASSERT_TRUE(pointerEvent != nullptr);
    auto pointerAction = pointerEvent->GetPointerAction();
    ASSERT_TRUE(pointerAction == MMI::PointerEvent::POINTER_ACTION_PULL_MOVE ||
                pointerAction == MMI::PointerEvent::POINTER_ACTION_PULL_UP ||
                pointerAction == MMI::PointerEvent::POINTER_ACTION_PULL_IN_WINDOW ||
                pointerAction == MMI::PointerEvent::POINTER_ACTION_PULL_OUT_WINDOW);
    ASSERT_TRUE(!pointerEvent->GetBuffer().empty());
    MMI::PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem);
    if (callback_ != nullptr && pointerItem.GetDisplayX() == DRAG_DST_X && pointerItem.GetDisplayY() == DRAG_DST_Y) {
        callback_();
    }
}

/**
 * @tc.name: InteractionManagerTest_PrepareCoordination
 * @tc.desc: Prepare coordination
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_PrepareCoordination, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_BASIC, g_basics, sizeof(g_basics) / sizeof(g_basics[0]));
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto fun = [&promiseFlag](const std::string &listener, const CoordinationMsgInfo &coordinationMessages) {
        FI_HILOGD("Prepare coordination success, listener:%{public}s", listener.c_str());
        promiseFlag.set_value(true);
    };
    bool isCompatible = true;
    int32_t ret = InteractionManager::GetInstance()->PrepareCoordination(fun, isCompatible);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    ASSERT_EQ(ret, RET_OK);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) != std::future_status::timeout);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COORDINATION
    RemovePermission();
}

/**
 * @tc.name: InteractionManagerTest_RegisterCoordinationListener_001
 * @tc.desc: Register coordination listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_RegisterCoordinationListener_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_BASIC, g_basics, sizeof(g_basics) / sizeof(g_basics[0]));
    std::shared_ptr<ICoordinationListener> consumer = nullptr;
    bool isCompatible = true;
    int32_t ret = InteractionManager::GetInstance()->RegisterCoordinationListener(consumer, isCompatible);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    ASSERT_EQ(ret, RET_ERR);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COORDINATION
    RemovePermission();
}

/**
 * @tc.name: InteractionManagerTest_RegisterCoordinationListener_002
 * @tc.desc: Register coordination listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_RegisterCoordinationListener_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    SetPermission(SYSTEM_BASIC, g_basics, sizeof(g_basics) / sizeof(g_basics[0]));
    class CoordinationListenerTest : public ICoordinationListener {
    public:
        CoordinationListenerTest() : ICoordinationListener() {}
        void OnCoordinationMessage(const std::string &networkId, CoordinationMessage msg) override
        {
            FI_HILOGD("Register coordination listener test");
            (void) networkId;
        };
    };
    std::shared_ptr<CoordinationListenerTest> consumer =
        std::make_shared<CoordinationListenerTest>();
    bool isCompatible = true;
    int32_t ret = InteractionManager::GetInstance()->RegisterCoordinationListener(consumer, isCompatible);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    ASSERT_EQ(ret, RET_OK);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COORDINATION
    ret = InteractionManager::GetInstance()->UnregisterCoordinationListener(consumer, isCompatible);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    ASSERT_EQ(ret, RET_OK);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COORDINATION
    RemovePermission();
}

/**
 * @tc.name: InteractionManagerTest_RegisterCoordinationListener_003
 * @tc.desc: Register coordination listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_RegisterCoordinationListener_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    FI_HILOGD("InteractionManagerTest_RegisterCoordinationListener_003 enter");
    SetPermission(SYSTEM_BASIC, g_basics, sizeof(g_basics) / sizeof(g_basics[0]));
    class CoordinationListenerTest : public ICoordinationListener {
    public:
        CoordinationListenerTest() : ICoordinationListener() {}
        void OnCoordinationMessage(const std::string &networkId, CoordinationMessage msg) override
        {
            FI_HILOGD("Register coordination listener test");
            (void) networkId;
        };
    };
    std::shared_ptr<CoordinationListenerTest> consumer =
        std::make_shared<CoordinationListenerTest>();
    bool isCompatible = true;
    int32_t ret = InteractionManager::GetInstance()->RegisterCoordinationListener(consumer, isCompatible);
    #ifdef OHOS_BUILD_ENABLE_COORDINATION
        ASSERT_EQ(ret, RET_OK);
    #else
        ASSERT_EQ(ret, ERROR_UNSUPPORT);
    #endif // OHOS_BUILD_ENABLE_COORDINATION
        ret = InteractionManager::GetInstance()->RegisterCoordinationListener(consumer, isCompatible);
    #ifdef OHOS_BUILD_ENABLE_COORDINATION
        ASSERT_EQ(ret, RET_ERR);
    #else
        ASSERT_EQ(ret, ERROR_UNSUPPORT);
    #endif // OHOS_BUILD_ENABLE_COORDINATION
        ret = InteractionManager::GetInstance()->UnregisterCoordinationListener(consumer, isCompatible);
    #ifdef OHOS_BUILD_ENABLE_COORDINATION
        ASSERT_EQ(ret, RET_OK);
    #else
        ASSERT_EQ(ret, ERROR_UNSUPPORT);
    #endif // OHOS_BUILD_ENABLE_COORDINATION
    RemovePermission();
    FI_HILOGD("InteractionManagerTest_RegisterCoordinationListener_003 finish");
}

/**
 * @tc.name: InteractionManagerTest_ActivateCoordination
 * @tc.desc: Activate coordination
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_ActivateCoordination, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_BASIC, g_basics, sizeof(g_basics) / sizeof(g_basics[0]));
    std::string remoteNetworkId("");
    int32_t startDeviceId = -1;
    auto fun = [](const std::string &listener, const CoordinationMsgInfo &coordinationMessages) {
        FI_HILOGD("Start coordination success");
        (void) listener;
    };
    bool isCompatible = true;
    int32_t ret = InteractionManager::GetInstance()->ActivateCoordination(remoteNetworkId, startDeviceId,
        fun, isCompatible);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    ASSERT_TRUE((ret == RET_OK || ret == COMMON_PERMISSION_CHECK_ERROR || ret == COMMON_NOT_ALLOWED_DISTRIBUTED));
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COORDINATION
    RemovePermission();
}

/**
 * @tc.name: InteractionManagerTest_DeactivateCoordination
 * @tc.desc: Deactivate coordination
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_DeactivateCoordination, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_BASIC, g_basics, sizeof(g_basics) / sizeof(g_basics[0]));
    auto fun = [](const std::string &listener, const CoordinationMsgInfo &coordinationMessages) {
        FI_HILOGD("Stop coordination success");
        (void) listener;
    };
    bool isCompatible = true;
    int32_t ret = InteractionManager::GetInstance()->DeactivateCoordination(false, fun, isCompatible);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    ASSERT_EQ(ret, RET_OK);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
    ret = InteractionManager::GetInstance()->DeactivateCoordination(true, fun, isCompatible);
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COORDINATION
    RemovePermission();
}

/**
 * @tc.name: InteractionManagerTest_GetCoordinationState_Abnormal
 * @tc.desc: Get coordination state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_GetCoordinationState_Abnormal, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_BASIC, g_basics, sizeof(g_basics) / sizeof(g_basics[0]));
    const std::string networkId("");
    auto fun = [](bool state) {
        FI_HILOGD("Get coordination state failed, state:%{public}d", state);
    };
    bool isCompatible = true;
    int32_t ret = InteractionManager::GetInstance()->GetCoordinationState(networkId, fun, isCompatible);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    ASSERT_EQ(ret, RET_OK);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COORDINATION
    RemovePermission();
}

/**
 * @tc.name: InteractionManagerTest_GetCoordinationState_Normal
 * @tc.desc: Get coordination state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_GetCoordinationState_Normal, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_BASIC, g_basics, sizeof(g_basics) / sizeof(g_basics[0]));
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    const std::string networkId("networkId");
    auto fun = [&promiseFlag](bool state) {
        FI_HILOGD("Get coordination state success, state:%{public}d", state);
        promiseFlag.set_value(true);
    };
    bool isCompatible = true;
    int32_t ret = InteractionManager::GetInstance()->GetCoordinationState(networkId, fun, isCompatible);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    ASSERT_EQ(ret, RET_OK);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) != std::future_status::timeout);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COORDINATION
    RemovePermission();
}

/**
 * @tc.name: InteractionManagerTest_GetCoordinationState_Sync
 * @tc.desc: Get coordination state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_GetCoordinationState_Sync, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_BASIC, g_basics, sizeof(g_basics) / sizeof(g_basics[0]));
    const std::string udId("Default");
    bool state { false };
    int32_t ret = InteractionManager::GetInstance()->GetCoordinationState(udId, state);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    ASSERT_EQ(ret, RET_OK);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COORDINATION
    RemovePermission();
}

/**
 * @tc.name: InteractionManagerTest_UnregisterCoordinationListener
 * @tc.desc: Unregister coordination listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_UnregisterCoordinationListener, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_BASIC, g_basics, sizeof(g_basics) / sizeof(g_basics[0]));
    std::shared_ptr<ICoordinationListener> consumer = nullptr;
    bool isCompatible = true;
    int32_t ret = InteractionManager::GetInstance()->UnregisterCoordinationListener(consumer, isCompatible);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    ASSERT_EQ(ret, RET_OK);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COORDINATION
    RemovePermission();
}

/**
 * @tc.name: InteractionManagerTest_UnprepareCoordination
 * @tc.desc: Prepare coordination
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_UnprepareCoordination, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_BASIC, g_basics, sizeof(g_basics) / sizeof(g_basics[0]));
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto fun = [&promiseFlag](const std::string &listener, const CoordinationMsgInfo &coordinationMessages) {
        FI_HILOGD("Prepare coordination success, listener:%{public}s", listener.c_str());
        promiseFlag.set_value(true);
    };
    bool isCompatible = true;
    int32_t ret = InteractionManager::GetInstance()->UnprepareCoordination(fun, isCompatible);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    ASSERT_EQ(ret, RET_OK);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) != std::future_status::timeout);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COORDINATION
    RemovePermission();
}


class HotAreaListenerTest : public IHotAreaListener {
public:
    HotAreaListenerTest() {}
    explicit HotAreaListenerTest(std::string name) : testName_(name) {}
    void OnHotAreaMessage(int32_t displayX, int32_t displayY, HotAreaType msg, bool isEdge) override
    {
        if (testName_.empty()) {
            testName_ = std::string("HOT_AREA");
        }
        FI_HILOGD("%{public}s, type:%{public}s, isEdge:%{public}d, displayX:%{public}d, displayY:%{public}d",
            testName_.c_str(), ShowMessage(msg).c_str(), isEdge, displayX, displayY);
    };

private:
    std::string ShowMessage(HotAreaType msg)
    {
        std::string type = "none-area";
        const std::map<HotAreaType, std::string> areaType = {
            { HotAreaType::AREA_LEFT, "left-area"},
            { HotAreaType::AREA_RIGHT, "right-area"},
            { HotAreaType::AREA_TOP, "top-area"},
            { HotAreaType::AREA_BOTTOM, "bottom-area"}
        };
        auto item = areaType.find(msg);
        if (item != areaType.end()) {
            type = item->second;
        }
        return type;
    }

private:
    std::string testName_;
};

/**
 * @tc.name: AddHotAreaListener_001
 * @tc.desc: Add hot area listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, AddHotAreaListener_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_BASIC, g_basics, sizeof(g_basics) / sizeof(g_basics[0]));
    auto listener = std::make_shared<HotAreaListenerTest>(std::string("HOT_AREA"));
    int32_t ret = InteractionManager::GetInstance()->AddHotAreaListener(listener);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    ASSERT_EQ(ret, RET_OK);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COORDINATION
    ret = InteractionManager::GetInstance()->RemoveHotAreaListener(listener);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    ASSERT_EQ(ret, RET_OK);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COORDINATION
    RemovePermission();
}

/**
 * @tc.name: AddHotAreaListener_002
 * @tc.desc: Add hot area listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, AddHotAreaListener_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    SetPermission(SYSTEM_BASIC, g_basics, sizeof(g_basics) / sizeof(g_basics[0]));
#ifndef OHOS_BUILD_PC_PRODUCT
    sptr<Rosen::Display> display = Rosen::DisplayManager::GetInstance().GetDisplayById(0);
#else
    sptr<Rosen::Display> display = Rosen::DisplayManager::GetInstance().GetAvailableDisplayById(0);
#endif // OHOS_BUILD_PC_PRODUCT
    CHKPV(display);
    g_screenWidth = display->GetWidth();
    g_screenHeight = display->GetHeight();
    auto listener = std::make_shared<HotAreaListenerTest>(std::string("HOT_AREA"));
    int32_t ret = InteractionManager::GetInstance()->AddHotAreaListener(listener);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    ASSERT_EQ(ret, RET_OK);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COORDINATION
    SimulateMovePointerEvent({ HOT_AREA_STEP, HOT_AREA_COOR }, { HOT_AREA_STEP - HOT_AREA_SPAN, HOT_AREA_COOR },
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, true);
    SimulateMovePointerEvent({ HOT_AREA_COOR, HOT_AREA_STEP }, { HOT_AREA_COOR, HOT_AREA_STEP - HOT_AREA_SPAN },
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, true);
    SimulateMovePointerEvent({ g_screenWidth - HOT_AREA_STEP, HOT_AREA_COOR },
        { g_screenWidth - HOT_AREA_SPAN, HOT_AREA_COOR },
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, true);
    SimulateMovePointerEvent({ HOT_AREA_COOR, g_screenHeight - HOT_AREA_STEP },
        { HOT_AREA_COOR, g_screenHeight - HOT_AREA_SPAN },
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, true);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_TOUCH_DOWN_MS));
    SetPermission(SYSTEM_BASIC, g_basics, sizeof(g_basics) / sizeof(g_basics[0]));
    ret = InteractionManager::GetInstance()->RemoveHotAreaListener(listener);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    ASSERT_EQ(ret, RET_OK);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COORDINATION
    RemovePermission();
}

/**
 * @tc.name: Set
 * @tc.desc: Set dampling coefficient.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_SetDamplingCoefficient, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_BASIC, g_basics, sizeof(g_basics) / sizeof(g_basics[0]));
    constexpr double damplingCoefficient { 0.1 };
    auto ret = InteractionManager::GetInstance()->SetDamplingCoefficient(
        COORDINATION_DAMPLING_RIGHT, damplingCoefficient);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InteractionManagerTest_Draglistener_Mouse
 * @tc.desc: Drag listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_Draglistener_Mouse, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (g_deviceMouseId < 0) {
        ASSERT_TRUE(g_deviceMouseId < 0);
    } else {
        auto listener = std::make_shared<DragListenerTest>(std::string("Draglistener_Mouse"));
        int32_t ret = InteractionManager::GetInstance()->AddDraglistener(listener);
        ASSERT_EQ(ret, RET_OK);
        std::promise<bool> promiseFlag;
        std::future<bool> futureFlag = promiseFlag.get_future();
        auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
            FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
                notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
            promiseFlag.set_value(true);
        };
        SimulateDownPointerEvent(
            { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID);
        std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
            MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
        ASSERT_TRUE(dragData);
        ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
            std::make_shared<UnitTestStartDragListener>(callback));
        ASSERT_EQ(ret, RET_OK);
        ret = InteractionManager::GetInstance()->SetDragWindowVisible(true);
        EXPECT_EQ(ret, RET_OK);
        SimulateMovePointerEvent({ DRAG_SRC_X, DRAG_SRC_Y }, { DRAG_DST_X, DRAG_DST_Y },
            MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, true);
        DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
        InteractionManager::GetInstance()->StopDrag(dropResult);
        ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
            std::future_status::timeout);
        ret = InteractionManager::GetInstance()->RemoveDraglistener(listener);
        ASSERT_EQ(ret, RET_OK);
    }
}

/**
 * @tc.name: InteractionManagerTest_Draglistener_Touch
 * @tc.desc: Drag listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_Draglistener_Touch, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (g_deviceTouchId < 0) {
        ASSERT_TRUE(g_deviceTouchId < 0);
    } else {
        auto dragListener = std::make_shared<DragListenerTest>(std::string("Draglistener_Touch"));
        int32_t ret = InteractionManager::GetInstance()->AddDraglistener(dragListener);
        ASSERT_EQ(ret, RET_OK);
        std::promise<bool> promiseFlag;
        std::future<bool> futureFlag = promiseFlag.get_future();
        auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
            FI_HILOGD("displayX:%{public}d, displayY:%{public}d, target:%{public}d, result:%{public}d",
                notifyMessage.displayX, notifyMessage.displayY, notifyMessage.targetPid, notifyMessage.result);
            promiseFlag.set_value(true);
        };
        SimulateDownPointerEvent(
            { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID);
        std::optional<DragData> dragData = CreateDragData({ MAX_PIXEL_MAP_WIDTH, MAX_PIXEL_MAP_HEIGHT },
            MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
        ASSERT_TRUE(dragData);
        ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
            std::make_shared<UnitTestStartDragListener>(callback));
        ASSERT_EQ(ret, RET_OK);
        SimulateMovePointerEvent({ DRAG_SRC_X, DRAG_SRC_Y }, { DRAG_DST_X, DRAG_DST_Y },
            MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, true);
        DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
        InteractionManager::GetInstance()->StopDrag(dropResult);
        ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
            std::future_status::timeout);
        ret = InteractionManager::GetInstance()->RemoveDraglistener(dragListener);
        ASSERT_EQ(ret, RET_OK);
    }
}

/**
 * @tc.name: InteractionManagerTest_Draglistener
 * @tc.desc: Drag listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_Draglistener, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (g_deviceTouchId < 0) {
        ASSERT_TRUE(g_deviceTouchId < 0);
    } else {
        int32_t ret = RET_ERR;
        std::vector<std::shared_ptr<DragListenerTest>> dragListeners;
        constexpr size_t listenerCount = 5;
        for (size_t i = 0; i < listenerCount; ++i) {
            std::string moduleName = "Draglistener_" + std::to_string(i);
            auto listener = std::make_shared<DragListenerTest>(moduleName);
            ret = InteractionManager::GetInstance()->AddDraglistener(listener);
            if (ret == RET_OK) {
                dragListeners.push_back(listener);
            }
        }
        SimulateDownPointerEvent(
            { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID);
        std::optional<DragData> dragData = CreateDragData({ MAX_PIXEL_MAP_WIDTH, MAX_PIXEL_MAP_HEIGHT },
            MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
        ASSERT_TRUE(dragData);
        std::promise<bool> promiseFlag;
        std::future<bool> futureFlag = promiseFlag.get_future();
        auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
            FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
                notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
            promiseFlag.set_value(true);
        };
        ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
            std::make_shared<UnitTestStartDragListener>(callback));
        ASSERT_EQ(ret, RET_OK);
        SimulateMovePointerEvent({ DRAG_SRC_X, DRAG_SRC_Y }, { DRAG_DST_X, DRAG_DST_Y },
            MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, true);
        DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
        InteractionManager::GetInstance()->StopDrag(dropResult);
        ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
            std::future_status::timeout);
        for (const auto &listener : dragListeners) {
            ret = InteractionManager::GetInstance()->RemoveDraglistener(listener);
            EXPECT_EQ(ret, RET_OK);
        }
    }
}

/**
 * @tc.name: InteractionManagerTest_SubscriptListener_001
 * @tc.desc: SubscriptListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_SubscriptListener_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (g_deviceTouchId < 0) {
        ASSERT_TRUE(g_deviceTouchId < 0);
    } else {
        int32_t ret = RET_ERR;
        std::vector<std::shared_ptr<SubscriptListenerTest>> subscriptListeners;
        for (size_t i = 0; i < RECIVE_LOOP_COUNT; ++i) {
            std::string moduleName = "SubscriptListener_" + std::to_string(i);
            auto listener = std::make_shared<SubscriptListenerTest>(moduleName);
            ret = InteractionManager::GetInstance()->AddSubscriptListener(listener);
            EXPECT_EQ(ret, RET_OK);
            subscriptListeners.push_back(listener);
        }
        std::promise<bool> promiseFlag;
        std::future<bool> futureFlag = promiseFlag.get_future();
        auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
            FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
                notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
            promiseFlag.set_value(true);
        };
        std::optional<DragData> dragData = CreateDragData({ MAX_PIXEL_MAP_WIDTH, MAX_PIXEL_MAP_HEIGHT },
            MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
        ASSERT_TRUE(dragData);
        ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
            std::make_shared<UnitTestStartDragListener>(callback));
        ASSERT_EQ(ret, RET_OK);
        SimulateMovePointerEvent({ DRAG_SRC_X, DRAG_SRC_Y }, { DRAG_DST_X, DRAG_DST_Y },
            MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, true);
        DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
        InteractionManager::GetInstance()->StopDrag(dropResult);
        ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
            std::future_status::timeout);
        for (auto listener : subscriptListeners) {
            ret = InteractionManager::GetInstance()->RemoveSubscriptListener(listener);
            EXPECT_EQ(ret, RET_OK);
        }
    }
}

/**
 * @tc.name: InteractionManagerTest_SubscriptListener_002
 * @tc.desc: SubscriptListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_SubscriptListener_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (g_deviceTouchId < 0) {
        ASSERT_TRUE(g_deviceTouchId < 0);
    } else {
        int32_t ret = RET_ERR;
        auto listener = std::make_shared<SubscriptListenerTest>("SubscriptListener");
        ret = InteractionManager::GetInstance()->AddSubscriptListener(listener);
        ASSERT_EQ(ret, RET_OK);
        std::promise<bool> promiseFlag;
        std::future<bool> futureFlag = promiseFlag.get_future();
        auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
            FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
                notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
            promiseFlag.set_value(true);
        };
        std::optional<DragData> dragData = CreateDragData({ MAX_PIXEL_MAP_WIDTH, MAX_PIXEL_MAP_HEIGHT },
            MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
        ASSERT_TRUE(dragData);
        ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
            std::make_shared<UnitTestStartDragListener>(callback));
        ASSERT_EQ(ret, RET_OK);
        ret = InteractionManager::GetInstance()->SetDragWindowVisible(true);
        ASSERT_EQ(ret, RET_OK);
        DragCursorStyle style = DragCursorStyle::COPY;
        ret = InteractionManager::GetInstance()->UpdateDragStyle(style);
        ASSERT_EQ(ret, RET_OK);
        style = DragCursorStyle::MOVE;
        ret = InteractionManager::GetInstance()->UpdateDragStyle(style);
        ASSERT_EQ(ret, RET_OK);
        SimulateMovePointerEvent({ DRAG_SRC_X, DRAG_SRC_Y }, { DRAG_DST_X, DRAG_DST_Y },
            MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, true);
        DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
        InteractionManager::GetInstance()->StopDrag(dropResult);
        ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
            std::future_status::timeout);
        DragCursorStyle recvStyle = listener->GetDragStyle();
        FI_HILOGD("Recived style:%{public}d, expected style:%{public}d", static_cast<int32_t>(recvStyle),
            static_cast<int32_t>(style));
        ret = InteractionManager::GetInstance()->RemoveSubscriptListener(listener);
        ASSERT_EQ(ret, RET_OK);
    }
}

/**
 * @tc.name: InteractionManagerTest_StartDrag_Mouse
 * @tc.desc: Start Drag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_StartDrag_Mouse, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (g_deviceMouseId < 0) {
        ASSERT_TRUE(g_deviceMouseId < 0);
    } else {
        std::promise<bool> promiseFlag;
        std::future<bool> futureFlag = promiseFlag.get_future();
        auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
            FI_HILOGD("Param displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
                notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
            promiseFlag.set_value(true);
        };
        SimulateDownPointerEvent(
            { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID);
        std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
            MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
        ASSERT_TRUE(dragData);
        int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
            std::make_shared<UnitTestStartDragListener>(callback));
        ASSERT_EQ(ret, RET_OK);
        ret = InteractionManager::GetInstance()->SetDragWindowVisible(true);
        InteractionManager::GetInstance()->SetDragWindowScreenId(TOUCH_POINTER_ID, TOUCH_POINTER_ID);
        EXPECT_EQ(ret, RET_OK);
        SimulateMovePointerEvent({ DRAG_SRC_X, DRAG_SRC_Y }, { DRAG_DST_X, DRAG_DST_Y },
            MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, true);
        DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
        InteractionManager::GetInstance()->StopDrag(dropResult);
        ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
            std::future_status::timeout);
    }
}

/**
 * @tc.name: InteractionManagerTest_StartDrag_Failed_Mouse
 * @tc.desc: Start Drag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_StartDrag_Failed_Mouse, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (g_deviceMouseId < 0) {
        ASSERT_TRUE(g_deviceMouseId < 0);
    } else {
        std::promise<bool> promiseFlag;
        std::future<bool> futureFlag = promiseFlag.get_future();
        SimulateDownPointerEvent(
            { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID);
        auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
            FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
                notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
            promiseFlag.set_value(true);
        };
        std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
            MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
        ASSERT_TRUE(dragData);

        int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(), nullptr);
        ASSERT_EQ(ret, RET_ERR);
        dragData->shadowInfos = {};
        ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
            std::make_shared<UnitTestStartDragListener>(callback));
        ASSERT_EQ(ret, ERR_INVALID_VALUE);
    }
}

/**
 * @tc.name: InteractionManagerTest_StopDrag_Mouse
 * @tc.desc: Stop drag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_StopDrag_Mouse, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (g_deviceMouseId < 0) {
        ASSERT_TRUE(g_deviceMouseId < 0);
    } else {
        std::promise<bool> promiseFlag;
        std::future<bool> futureFlag = promiseFlag.get_future();
        auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
            FI_HILOGD("displayX:%{public}d, displayY:%{public}d, target:%{public}d, result:%{public}d",
                notifyMessage.displayX, notifyMessage.displayY, notifyMessage.targetPid, notifyMessage.result);
            promiseFlag.set_value(true);
        };
        SimulateDownPointerEvent(
            { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID);
        std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
            MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
        ASSERT_TRUE(dragData);
        int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
            std::make_shared<UnitTestStartDragListener>(callback));
        ASSERT_EQ(ret, RET_OK);
        DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
        InteractionManager::GetInstance()->StopDrag(dropResult);
        ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
            std::future_status::timeout);
    }
}

/**
 * @tc.name: InteractionManagerTest_StopDrag_Failed_Mouse
 * @tc.desc: Stop drag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_StopDrag_Failed_Mouse, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (g_deviceMouseId < 0) {
        ASSERT_TRUE(g_deviceMouseId < 0);
    } else {
        SimulateDownPointerEvent(
            { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID);
        std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
            MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
        ASSERT_TRUE(dragData);
        int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(), nullptr);
        ASSERT_EQ(ret, RET_ERR);
        DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
        ret = InteractionManager::GetInstance()->StopDrag(dropResult);
        ASSERT_EQ(ret, RET_ERR);
    }
}

/**
 * @tc.name: InteractionManagerTest_StartDrag_Touch
 * @tc.desc: Start Drag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_StartDrag_Touch, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (g_deviceTouchId < 0) {
        ASSERT_TRUE(g_deviceTouchId < 0);
    } else {
        SimulateDownPointerEvent(
            { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_TOUCH_DOWN_MS));
        std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
            MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
        ASSERT_TRUE(dragData);
        std::promise<bool> promiseFlag;
        std::future<bool> futureFlag = promiseFlag.get_future();
        auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
            FI_HILOGD("Start drag, displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
                notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
            promiseFlag.set_value(true);
        };
        int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
            std::make_shared<UnitTestStartDragListener>(callback));
        ASSERT_EQ(ret, RET_OK);
        ret = InteractionManager::GetInstance()->SetDragWindowVisible(true);
        EXPECT_EQ(ret, RET_OK);
        SimulateMovePointerEvent({ DRAG_SRC_X, DRAG_SRC_Y }, { DRAG_DST_X, DRAG_DST_Y },
            MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, true);
        DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
        InteractionManager::GetInstance()->StopDrag(dropResult);
        ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
            std::future_status::timeout);
    }
}

/**
 * @tc.name: InteractionManagerTest_StopDrag_Touch
 * @tc.desc: Stop drag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_StopDrag_Touch, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (g_deviceTouchId < 0) {
        ASSERT_TRUE(g_deviceTouchId < 0);
    } else {
        std::promise<bool> promiseFlag;
        std::future<bool> future = promiseFlag.get_future();
        auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
            FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
                notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
            promiseFlag.set_value(true);
        };
        SimulateDownPointerEvent(
            { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_TOUCH_DOWN_MS));
        std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
            MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
        ASSERT_TRUE(dragData);
        int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
            std::make_shared<UnitTestStartDragListener>(callback));
        ASSERT_EQ(ret, RET_OK);
        DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
        InteractionManager::GetInstance()->StopDrag(dropResult);
        ASSERT_TRUE(future.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
            std::future_status::timeout);
    }
}

/**
 * @tc.name: GetDragTargetPid_Mouse
 * @tc.desc: Get the target pid dragged by the mouse
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, GetDragTargetPid_Mouse, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (g_deviceMouseId < 0) {
        ASSERT_TRUE(g_deviceMouseId < 0);
    } else {
        std::promise<bool> promiseStopFlag;
        std::future<bool> futureStopFlag = promiseStopFlag.get_future();
        auto callback = [&promiseStopFlag](const DragNotifyMsg& notifyMessage) {
            FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
                notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
            promiseStopFlag.set_value(true);
        };
        SimulateDownPointerEvent(
            { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID);
        std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
            MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
        ASSERT_TRUE(dragData);
        int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
            std::make_shared<UnitTestStartDragListener>(callback));
        ASSERT_EQ(ret, RET_OK);
        ret = InteractionManager::GetInstance()->SetDragWindowVisible(true);
        EXPECT_EQ(ret, RET_OK);
        ret = InteractionManager::GetInstance()->UpdateDragStyle(DragCursorStyle::DEFAULT);
        ASSERT_EQ(ret, RET_OK);
        int32_t pid = InteractionManager::GetInstance()->GetDragTargetPid();
        FI_HILOGI("Target pid:%{public}d", pid);
        ASSERT_TRUE(pid > 0);
        DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
        InteractionManager::GetInstance()->StopDrag(dropResult);
        ASSERT_TRUE(futureStopFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
            std::future_status::timeout);
    }
}

/**
 * @tc.name: GetDragTargetPid_Touch
 * @tc.desc: Get the target pid dragged by the touchscreen
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, GetDragTargetPid_Touch, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (g_deviceTouchId < 0) {
        ASSERT_TRUE(g_deviceTouchId < 0);
    } else {
        std::promise<bool> promiseStopFlag;
        std::future<bool> futureStopFlag = promiseStopFlag.get_future();
        auto callback = [&promiseStopFlag](const DragNotifyMsg& notifyMessage) {
            FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
                notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
            promiseStopFlag.set_value(true);
        };
        SimulateDownPointerEvent(
            { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_TOUCH_DOWN_MS));
        std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
            MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
        ASSERT_TRUE(dragData);
        int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
            std::make_shared<UnitTestStartDragListener>(callback));
        ASSERT_EQ(ret, RET_OK);
        ret = InteractionManager::GetInstance()->SetDragWindowVisible(true);
        EXPECT_EQ(ret, RET_OK);
        ret = InteractionManager::GetInstance()->UpdateDragStyle(DragCursorStyle::COPY);
        ASSERT_EQ(ret, RET_OK);
        int32_t pid = InteractionManager::GetInstance()->GetDragTargetPid();
        FI_HILOGI("Target pid:%{public}d", pid);
        ASSERT_TRUE(pid > 0);
        DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
        InteractionManager::GetInstance()->StopDrag(dropResult);
        ASSERT_TRUE(futureStopFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
            std::future_status::timeout);
    }
}

/**
 * @tc.name: TouchEventDispatch
 * @tc.desc: Dispatch the touchscreen events
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, TouchEventDispatch, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (g_deviceTouchId < 0) {
        ASSERT_TRUE(g_deviceTouchId < 0);
    } else {
        std::promise<bool> promiseFlag;
        std::future<bool> futureFlag = promiseFlag.get_future();
        auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
            FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
                notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
            promiseFlag.set_value(true);
        };
        SimulateDownPointerEvent(
            { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_TOUCH_DOWN_MS));
        std::optional<DragData> dragDataInfo = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
            MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID_INJECT, DISPLAY_ID,
            { DRAG_SRC_X, DRAG_SRC_Y });
        ASSERT_TRUE(dragDataInfo);
        int32_t result = InteractionManager::GetInstance()->StartDrag(dragDataInfo.value(),
            std::make_shared<UnitTestStartDragListener>(callback));
        ASSERT_EQ(result, RET_OK);
        result = InteractionManager::GetInstance()->SetDragWindowVisible(true);
        EXPECT_EQ(result, RET_OK);
        SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
        std::promise<bool> promiseEventFlag;
        std::future<bool> futureEventFlag = promiseEventFlag.get_future();
        auto callbackPtr = std::make_shared<InputEventCallbackTest>(
            [&promiseEventFlag]{promiseEventFlag.set_value(true);});
        int32_t monitorId = TestAddMonitor(callbackPtr);
        SimulateMovePointerEvent({ DRAG_SRC_X, DRAG_SRC_Y }, { DRAG_DST_X, DRAG_DST_Y },
            MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, true);
        ASSERT_TRUE(futureEventFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
            std::future_status::timeout);
        SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
        TestRemoveMonitor(monitorId);
        DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
        result = InteractionManager::GetInstance()->StopDrag(dropResult);
        ASSERT_EQ(result, RET_OK);
        ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
            std::future_status::timeout);
        RemovePermission();
    }
}

/**
 * @tc.name: MouseEventDispatch
 * @tc.desc: Dispatch the mouse events
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, MouseEventDispatch, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (g_deviceMouseId < 0) {
        ASSERT_TRUE(g_deviceMouseId < 0);
    } else {
        std::promise<bool> promiseFlag;
        std::future<bool> futureFlag = promiseFlag.get_future();
        auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
            FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
                notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
            promiseFlag.set_value(true);
        };
        SimulateDownPointerEvent(
            { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_MOUSE, 0);
        std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
            MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID_INJECT, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
        ASSERT_TRUE(dragData);
        int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
            std::make_shared<UnitTestStartDragListener>(callback));
        ASSERT_EQ(ret, RET_OK);
        ret = InteractionManager::GetInstance()->SetDragWindowVisible(true);
        EXPECT_EQ(ret, RET_OK);
        SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
        std::promise<bool> promiseEventFlag;
        std::future<bool> futureEventFlag = promiseEventFlag.get_future();
        auto callbackPtr = std::make_shared<InputEventCallbackTest>(
            [&promiseEventFlag]{promiseEventFlag.set_value(true);});
        int32_t monitorId = TestAddMonitor(callbackPtr);
        SimulateMovePointerEvent({ DRAG_SRC_X, DRAG_SRC_Y }, { DRAG_DST_X, DRAG_DST_Y },
            MMI::PointerEvent::SOURCE_TYPE_MOUSE, TOUCH_POINTER_ID, true);
        ASSERT_TRUE(futureEventFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
            std::future_status::timeout);
        SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
        TestRemoveMonitor(monitorId);
        DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
        ret = InteractionManager::GetInstance()->StopDrag(dropResult);
        ASSERT_EQ(ret, RET_OK);
        ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
            std::future_status::timeout);
    }
    RemovePermission();
}

/**
 * @tc.name: InteractionManagerTest_SetDragWindowVisible
 * @tc.desc: Set Drag Window Visible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_SetDragWindowVisible, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = InteractionManager::GetInstance()->SetDragWindowVisible(true);
    FI_HILOGD("ret:%{public}d", ret);
    ASSERT_EQ(ret, RET_ERR);
    ret = InteractionManager::GetInstance()->SetDragWindowVisible(false);
    FI_HILOGD("ret:%{public}d", ret);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InteractionManagerTest_GetShadowOffset
 * @tc.desc: Get Shadow Offset
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_GetShadowOffset, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t offsetX = 0;
    int32_t offsetY = 0;
    int32_t width = 0;
    int32_t height = 0;
    std::promise<bool> promise;
    std::future<bool> futureFlag = promise.get_future();
    auto callback = [&promise](const DragNotifyMsg& notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promise.set_value(true);
    };
    SimulateDownPointerEvent(
        { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_TOUCH_DOWN_MS));
    std::optional<DragData> dragDataInfo = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragDataInfo);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragDataInfo.value(),
        std::make_shared<UnitTestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    ret = InteractionManager::GetInstance()->GetShadowOffset(offsetX, offsetY, width, height);
    FI_HILOGD("offsetX:%{public}d, offsetY:%{public}d, width:%{public}d, height:%{public}d",
        offsetX, offsetY, width, height);
    ASSERT_EQ(ret, RET_OK);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) != std::future_status::timeout);
}

/**
 * @tc.name: GetUdKey_Mouse
 * @tc.desc: Get the udKey dragged by the mouse
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, GetUdKey_Mouse, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (g_deviceMouseId < 0) {
        ASSERT_TRUE(g_deviceMouseId < 0);
    } else {
        SimulateDownPointerEvent(
            { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID);
        std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
            MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
        ASSERT_TRUE(dragData);
        std::promise<bool> promiseFlag;
        std::future<bool> futureFlag = promiseFlag.get_future();
        auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
            FI_HILOGD("Get ud key, displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
                notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
            promiseFlag.set_value(true);
        };
        int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
            std::make_shared<UnitTestStartDragListener>(callback));
        ASSERT_EQ(ret, RET_OK);
        std::string udKey;
        ret = InteractionManager::GetInstance()->GetUdKey(udKey);
        ASSERT_EQ(ret, RET_OK);
        ASSERT_EQ(udKey, UD_KEY);
        DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
        ret = InteractionManager::GetInstance()->StopDrag(dropResult);
        ASSERT_EQ(ret, RET_OK);
        ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
            std::future_status::timeout);
    }
}

/**
 * @tc.name: GetUdKey_Touch
 * @tc.desc: Get the udKey dragged by the touchscreen
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, GetUdKey_Touch, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (g_deviceTouchId < 0) {
        ASSERT_TRUE(g_deviceTouchId < 0);
    } else {
        std::promise<bool> promiseFlag;
        std::future<bool> futureFlag = promiseFlag.get_future();
        auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
            FI_HILOGD("displayX:%{public}d, displayY:%{public}d, target:%{public}d, result:%{public}d",
                notifyMessage.displayX, notifyMessage.displayY, notifyMessage.targetPid, notifyMessage.result);
            promiseFlag.set_value(true);
        };
        SimulateDownPointerEvent(
            { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_TOUCH_DOWN_MS));
        std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
            MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
        ASSERT_TRUE(dragData);
        int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
            std::make_shared<UnitTestStartDragListener>(callback));
        ASSERT_EQ(ret, RET_OK);
        std::string udKey;
        ret = InteractionManager::GetInstance()->GetUdKey(udKey);
        ASSERT_EQ(ret, RET_OK);
        ASSERT_EQ(udKey, UD_KEY);
        DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
        ret = InteractionManager::GetInstance()->StopDrag(dropResult);
        ASSERT_EQ(ret, RET_OK);
        ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
            std::future_status::timeout);
    }
}

/**
 * @tc.name: GetDragData_Success
 * @tc.desc: Get the dragData from interface successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, GetDragData_Success, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (g_deviceTouchId < 0) {
        ASSERT_TRUE(g_deviceTouchId < 0);
    } else {
        std::promise<bool> promiseFlag;
        std::future<bool> futureFlag = promiseFlag.get_future();
        auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
            FI_HILOGD("Get drag data, displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
                notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
            promiseFlag.set_value(true);
        };
        SimulateDownPointerEvent(
            { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID);
        std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
            MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
        ASSERT_TRUE(dragData);
        int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
            std::make_shared<UnitTestStartDragListener>(callback));
        ASSERT_EQ(ret, RET_OK);

        DragData replyDragData;
        ret = InteractionManager::GetInstance()->GetDragData(replyDragData);
        ASSERT_EQ(ret, RET_OK);
        ASSERT_EQ(replyDragData, dragData.value());
        PrintDragData(replyDragData);
        SimulateUpPointerEvent(
            { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID);
        DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
        InteractionManager::GetInstance()->StopDrag(dropResult);
        ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
            std::future_status::timeout);
    }
}

/**
 * @tc.name: GetDragData_Failed
 * @tc.desc: Get the dragData from interface failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, GetDragData_Failed, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (g_deviceTouchId < 0) {
        ASSERT_TRUE(g_deviceTouchId < 0);
    } else {
        SimulateDownPointerEvent(
            { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_TOUCH_DOWN_MS));
        DragData dragData;
        int32_t ret = InteractionManager::GetInstance()->GetDragData(dragData);
        SimulateUpPointerEvent(
            { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID);
        ASSERT_EQ(ret, RET_ERR);
    }
}

/**
 * @tc.name: GetDragState
 * @tc.desc: Get the dragState from interface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, GetDragState, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
        FI_HILOGD("Drag state, displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    SimulateDownPointerEvent(
        { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID);
    std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<UnitTestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);

    DragState dragState;
    ret = InteractionManager::GetInstance()->GetDragState(dragState);
    FI_HILOGD("InteractionManager::dragState:%{public}d", dragState);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(dragState, DragState::START);

    SimulateUpPointerEvent(
        { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
    ret = InteractionManager::GetInstance()->GetDragState(dragState);
    FI_HILOGD("dragState:%{public}d", dragState);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(dragState, DragState::STOP);
}

/**
 * @tc.name: InteractionManagerTest_GetDragSummary
 * @tc.desc: Get drag summarys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_GetDragSummary, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragData);
    const std::string udType = "general.message";
    constexpr int64_t recordSize = 20;
    std::map<std::string, int64_t> summarys = { { udType, recordSize } };
    dragData.value().summarys = summarys;
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<UnitTestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    summarys.clear();
    ret = InteractionManager::GetInstance()->GetDragSummary(summarys);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(summarys[udType], recordSize);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
    InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: InteractionManagerTest_UpdatePreviewStyle
 * @tc.desc: Update drag item style
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_UpdatePreviewStyle, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    SimulateDownPointerEvent(
        { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID);
    std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<UnitTestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    ret = InteractionManager::GetInstance()->SetDragWindowVisible(true);
    EXPECT_EQ(ret, RET_OK);
    std::pair<int32_t, int32_t> enterPos { 500, 50 };
    std::pair<int32_t, int32_t> leavePos { 500, 200 };
    SimulateMovePointerEvent({ DRAG_SRC_X, DRAG_SRC_Y }, { enterPos.first, enterPos.second },
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, true);
    PreviewStyle previewStyleIn;
    previewStyleIn.types = { PreviewType::FOREGROUND_COLOR };
    previewStyleIn.foregroundColor = FOREGROUND_COLOR_IN;
    ret = InteractionManager::GetInstance()->UpdatePreviewStyle(previewStyleIn);
    EXPECT_EQ(ret, RET_OK);
    SimulateMovePointerEvent({ enterPos.first, enterPos.second }, { leavePos.first, leavePos.second },
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, true);
    PreviewStyle previewStyleOut;
    previewStyleOut.types = { PreviewType::FOREGROUND_COLOR };
    previewStyleOut.foregroundColor = FOREGROUND_COLOR_OUT;
    ret = InteractionManager::GetInstance()->UpdatePreviewStyle(previewStyleOut);
    EXPECT_EQ(ret, RET_OK);
    SimulateMovePointerEvent({ leavePos.first, leavePos.second }, { DRAG_DST_X, DRAG_DST_Y },
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, true);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
    InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}


/**
 * @tc.name: InteractionManagerTest_UpdatePreviewStyleWithAnimation
 * @tc.desc: Update drag item style with animation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_UpdatePreviewStyleWithAnimation, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    SimulateDownPointerEvent({ DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID);
    std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<UnitTestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    ret = InteractionManager::GetInstance()->SetDragWindowVisible(true);
    EXPECT_EQ(ret, RET_OK);
    std::pair<int32_t, int32_t> enterPos { 500, 50 };
    std::pair<int32_t, int32_t> leavePos { 500, 200 };
    SimulateMovePointerEvent({ DRAG_SRC_X, DRAG_SRC_Y }, { enterPos.first, enterPos.second },
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, true);
    PreviewStyle previewStyleIn;
    previewStyleIn.types = { PreviewType::FOREGROUND_COLOR };
    previewStyleIn.foregroundColor = FOREGROUND_COLOR_IN;
    PreviewAnimation animationIn;
    AssignToAnimation(animationIn);
    ret = InteractionManager::GetInstance()->UpdatePreviewStyleWithAnimation(previewStyleIn, animationIn);
    EXPECT_EQ(ret, RET_OK);
    SimulateMovePointerEvent({ enterPos.first, enterPos.second }, { leavePos.first, leavePos.second },
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, true);
    PreviewStyle previewStyleOut;
    previewStyleOut.types = { PreviewType::FOREGROUND_COLOR };
    previewStyleOut.foregroundColor = FOREGROUND_COLOR_OUT;
    PreviewAnimation animationOut;
    AssignToAnimation(animationOut);
    ret = InteractionManager::GetInstance()->UpdatePreviewStyleWithAnimation(previewStyleOut, animationOut);
    EXPECT_EQ(ret, RET_OK);
    SimulateMovePointerEvent({ leavePos.first, leavePos.second }, { DRAG_DST_X, DRAG_DST_Y },
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, true);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
    InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: InteractionManagerTest_GetExtraInfo
 * @tc.desc: Get extraInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_GetExtraInfo, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (g_deviceMouseId >= 0) {
        SimulateDownPointerEvent(
            { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID);
        std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
            MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
        ASSERT_TRUE(dragData);
        std::promise<bool> promiseFlag;
        std::future<bool> futureFlag = promiseFlag.get_future();
        auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
            FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
                notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
            promiseFlag.set_value(true);
        };
        int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
            std::make_shared<UnitTestStartDragListener>(callback));
        ASSERT_EQ(ret, RET_OK);
        std::string extraInfo;
        ret = InteractionManager::GetInstance()->GetExtraInfo(extraInfo);
        ASSERT_EQ(ret, RET_OK);
        ASSERT_EQ(extraInfo, EXTRA_INFO);
        DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
        ret = InteractionManager::GetInstance()->StopDrag(dropResult);
        ASSERT_EQ(ret, RET_OK);
        ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
            std::future_status::timeout);
    }
}

/**
 * @tc.name: TestDragDataUtil_Packer
 * @tc.desc: Pack up dragData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, TestDragDataUtil_Packer, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragData);
    Parcel parcel;
    int32_t ret = DragDataUtil::Marshalling(dragData.value(), parcel, false);
    ASSERT_EQ(ret, RET_OK);
    DragData dragDataFromParcel;
    ret = DragDataUtil::UnMarshalling(parcel, dragDataFromParcel, false);
    ASSERT_EQ(ret, RET_OK);
    ASSERT_EQ(dragData.value(), dragDataFromParcel);
}

/**
 * @tc.name: TestDragDataUtil_Packer_Cross
 * @tc.desc: Pack up dragData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, TestDragDataUtil_Packer_Cross, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragData);
    Parcel parcel;
    int32_t ret = DragDataUtil::Marshalling(dragData.value(), parcel, true);
    ASSERT_EQ(ret, RET_OK);
    DragData dragDataFromParcel;
    ret = DragDataUtil::UnMarshalling(parcel, dragDataFromParcel, true);
    ASSERT_EQ(ret, RET_OK);
    ASSERT_EQ(dragData.value(), dragDataFromParcel);
}

/**
 * @tc.name: InteractionManagerTest_GetDragAction_001
 * @tc.desc: Get drag action with no keyboard events of keys in dragging
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, GetDragAction_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<UnitTestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    DragAction dragAction { DragAction::INVALID };
    ret = InteractionManager::GetInstance()->GetDragAction(dragAction);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(dragAction, DragAction::MOVE);
    PrintDragAction(dragAction);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
    InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
    ret = InteractionManager::GetInstance()->GetDragAction(dragAction);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InteractionManagerTest_GetDragAction_002
 * @tc.desc: Get drag action with simple press and release keyboard events of keys in dragging
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, GetDragAction_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
        FI_HILOGD("DisplayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_INJECT_MS));
    std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID_INJECT, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<UnitTestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    ret = InteractionManager::GetInstance()->UpdateDragStyle(DragCursorStyle::MOVE);
    ASSERT_EQ(ret, RET_OK);
    SimulateMovePointerEvent({ DRAG_SRC_X, DRAG_SRC_Y }, { DRAG_DST_X, DRAG_DST_Y },
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, true);
    SimulateDownKeyEvent(MMI::KeyEvent::KEYCODE_CTRL_LEFT);
    DragAction dragAction { DragAction::INVALID };
    ret = InteractionManager::GetInstance()->GetDragAction(dragAction);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(dragAction, DragAction::COPY);
    PrintDragAction(dragAction);
    SimulateUpKeyEvent(MMI::KeyEvent::KEYCODE_CTRL_LEFT);
    ret = InteractionManager::GetInstance()->GetDragAction(dragAction);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(dragAction, DragAction::MOVE);
    PrintDragAction(dragAction);
    ClearUpKeyEvent();
    SimulateDownKeyEvent(MMI::KeyEvent::KEYCODE_A);
    ret = InteractionManager::GetInstance()->GetDragAction(dragAction);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(dragAction, DragAction::MOVE);
    PrintDragAction(dragAction);
    SimulateUpKeyEvent(MMI::KeyEvent::KEYCODE_A);
    ret = InteractionManager::GetInstance()->GetDragAction(dragAction);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(dragAction, DragAction::MOVE);
    PrintDragAction(dragAction);
    ClearUpKeyEvent();
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
    InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
    ret = InteractionManager::GetInstance()->GetDragAction(dragAction);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InteractionManagerTest_GetDragAction_003
 * @tc.desc: Get drag action with simple press and release keyboard events of keys in start drag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, GetDragAction_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (g_deviceMouseId < 0) {
        ASSERT_TRUE(g_deviceMouseId < 0);
    } else {
        int32_t ret = RET_ERR;
        std::promise<bool> promiseFlag;
        std::future<bool> futureFlag = promiseFlag.get_future();
        auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
            FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
                notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
            promiseFlag.set_value(true);
        };
        std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
            MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
        ASSERT_TRUE(dragData);
        ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
            std::make_shared<UnitTestStartDragListener>(callback));
        ASSERT_EQ(ret, RET_OK);
        ret = InteractionManager::GetInstance()->UpdateDragStyle(DragCursorStyle::MOVE);
        ASSERT_EQ(ret, RET_OK);
        DragAction dragAction { DragAction::INVALID };
        ret = InteractionManager::GetInstance()->GetDragAction(dragAction);
        EXPECT_EQ(ret, RET_OK);
        EXPECT_EQ(dragAction, DragAction::MOVE);
        PrintDragAction(dragAction);
        DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
        InteractionManager::GetInstance()->StopDrag(dropResult);
        ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
            std::future_status::timeout);
        ret = InteractionManager::GetInstance()->GetDragAction(dragAction);
        EXPECT_EQ(ret, RET_ERR);
    }
}

/**
 * @tc.name: InteractionManagerTest_GetDragAction_004
 * @tc.desc: Get drag action with multiple press and release keyboard events of keys in dragging
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, GetDragAction_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID_INJECT, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<UnitTestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    ret = InteractionManager::GetInstance()->UpdateDragStyle(DragCursorStyle::MOVE);
    ASSERT_EQ(ret, RET_OK);
    SimulateMovePointerEvent({ DRAG_SRC_X, DRAG_SRC_Y }, { DRAG_DST_X, DRAG_DST_Y },
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, true);
    SimulateDownKeyEvent(MMI::KeyEvent::KEYCODE_CTRL_LEFT);
    SimulateDownKeyEvent(MMI::KeyEvent::KEYCODE_A);
    DragAction dragAction { DragAction::INVALID };
    ret = InteractionManager::GetInstance()->GetDragAction(dragAction);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(dragAction, DragAction::COPY);
    SimulateUpKeyEvent(MMI::KeyEvent::KEYCODE_A);
    ret = InteractionManager::GetInstance()->GetDragAction(dragAction);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(dragAction, DragAction::COPY);
    ClearUpKeyEvent();
    SimulateDownKeyEvent(MMI::KeyEvent::KEYCODE_B);
    ret = InteractionManager::GetInstance()->GetDragAction(dragAction);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(dragAction, DragAction::COPY);
    SimulateUpKeyEvent(MMI::KeyEvent::KEYCODE_CTRL_LEFT);
    ret = InteractionManager::GetInstance()->GetDragAction(dragAction);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(dragAction, DragAction::MOVE);
    ClearUpKeyEvent();
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
    InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
    ret = InteractionManager::GetInstance()->GetDragAction(dragAction);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InteractionManagerTest_GetDragAction_005
 * @tc.desc: Get style notification with multiple press and release keyboard events of keys in dragging
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, GetDragAction_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<SubscriptListenerTest>("SubscriptListener");
    int32_t ret = InteractionManager::GetInstance()->AddSubscriptListener(listener);
    ASSERT_EQ(ret, RET_OK);
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID_INJECT, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragData);
    ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<UnitTestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    ret = InteractionManager::GetInstance()->UpdateDragStyle(DragCursorStyle::MOVE);
    ASSERT_EQ(ret, RET_OK);
    SimulateMovePointerEvent({ DRAG_SRC_X, DRAG_SRC_Y }, { DRAG_DST_X, DRAG_DST_Y },
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, true);
    DragCursorStyle recvStyle = listener->GetDragStyle();
    EXPECT_EQ(recvStyle, DragCursorStyle::MOVE);
    SimulateDownKeyEvent(MMI::KeyEvent::KEYCODE_CTRL_LEFT);
    SimulateDownKeyEvent(MMI::KeyEvent::KEYCODE_B);
    recvStyle = listener->GetDragStyle();
    EXPECT_EQ(recvStyle, DragCursorStyle::COPY);
    SimulateUpKeyEvent(MMI::KeyEvent::KEYCODE_CTRL_LEFT);
    ClearUpKeyEvent();
    recvStyle = listener->GetDragStyle();
    EXPECT_EQ(recvStyle, DragCursorStyle::MOVE);
    SimulateDownKeyEvent(MMI::KeyEvent::KEYCODE_CTRL_RIGHT);
    recvStyle = listener->GetDragStyle();
    EXPECT_EQ(recvStyle, DragCursorStyle::COPY);
    SimulateUpKeyEvent(MMI::KeyEvent::KEYCODE_B);
    ClearUpKeyEvent();
    recvStyle = listener->GetDragStyle();
    EXPECT_EQ(recvStyle, DragCursorStyle::COPY);
    SimulateUpKeyEvent(MMI::KeyEvent::KEYCODE_CTRL_RIGHT);
    ClearUpKeyEvent();
    recvStyle = listener->GetDragStyle();
    EXPECT_EQ(recvStyle, DragCursorStyle::MOVE);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
    InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
    ret = InteractionManager::GetInstance()->RemoveSubscriptListener(listener);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InteractionManagerTest_CheckDragBehavior_001
 * @tc.desc: Check drag behavior
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, CheckDragBehavior_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, dragBehavior:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.dragBehavior);
        ASSERT_EQ(notifyMessage.dragBehavior, DragBehavior::COPY);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<UnitTestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION,
        TARGET_MAIN_WINDOW, DragBehavior::COPY };
    InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: InteractionManagerTest_CheckDragBehavior_002
 * @tc.desc: Check drag behavior
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, CheckDragBehavior_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, dragBehavior:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.dragBehavior);
        ASSERT_EQ(notifyMessage.dragBehavior, DragBehavior::MOVE);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<UnitTestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION,
        TARGET_MAIN_WINDOW, DragBehavior::MOVE };
    InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: InteractionManagerTest_CheckDragBehavior_003
 * @tc.desc: Check drag behavior
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, CheckDragBehavior_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, dragBehavior:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.dragBehavior);
        ASSERT_EQ(notifyMessage.dragBehavior, DragBehavior::COPY);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<UnitTestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    ret = InteractionManager::GetInstance()->UpdateDragStyle(DragCursorStyle::COPY);
    ASSERT_EQ(ret, RET_OK);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: InteractionManagerTest_CheckDragBehavior_004
 * @tc.desc: Check drag behavior
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, CheckDragBehavior_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, dragBehavior:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.dragBehavior);
        ASSERT_EQ(notifyMessage.dragBehavior, DragBehavior::MOVE);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<UnitTestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: InteractionManagerTest_CheckDragBehavior_005
 * @tc.desc: Check drag behavior
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, CheckDragBehavior_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, dragBehavior:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.dragBehavior);
        ASSERT_EQ(notifyMessage.dragBehavior, DragBehavior::COPY);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<UnitTestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    int32_t targetMainWindow = 1;
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, targetMainWindow };
    InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: InteractionManagerTest_CheckDragBehavior_006
 * @tc.desc: Check drag behavior
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, CheckDragBehavior_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, dragBehavior:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.dragBehavior);
        ASSERT_EQ(notifyMessage.dragBehavior, DragBehavior::UNKNOWN);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<UnitTestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    DragDropResult dropResult { DragResult::DRAG_FAIL, HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: InteractionManagerTest_StartDrag_Shadow
 * @tc.desc: Check drag shadow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_StartDrag_Shadow, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
        FI_HILOGD("Param displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    SimulateDownPointerEvent(
        { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID);
    std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragData);
    dragData->filterInfo = "{ \"dip_scale\": 3.5, \"drag_shadow_offsetX\": 30, \"drag_shadow_offsetY\": 30, "
        "\"drag_shadow_argb\": 4294967295, \"drag_shadow_path\": \"M 10 10 H 80 V 80 H 10 L 10 10\", "
		"\"shadow_color_strategy\": 0, \"shadow_is_hardwareacceleration\": true, \"shadow_elevation\": 120, "
		"\"drag_type\": \"text\", \"shadow_enable\": true }";
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<UnitTestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    ret = InteractionManager::GetInstance()->SetDragWindowVisible(true);
    EXPECT_EQ(ret, RET_OK);
    SimulateMovePointerEvent({ DRAG_SRC_X, DRAG_SRC_Y }, { DRAG_DST_X, DRAG_DST_Y },
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, true);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
    InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: InteractionManagerTest_StartDrag_ShadowAlpha
 * @tc.desc: Check drag shadow alpha
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_StartDrag_ShadowAlpha, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
        FI_HILOGD("Param displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    SimulateDownPointerEvent(
        { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID);
    std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragData);
    dragData->filterInfo = "{ \"dip_scale\": 3.5, \"drag_shadow_offsetX\": 30, \"drag_shadow_offsetY\": 30, "
        "\"drag_shadow_argb\": 872415231, \"drag_shadow_path\": \"M 10 10 H 80 V 80 H 10 L 10 10\", "
		"\"shadow_color_strategy\": 0, \"shadow_is_hardwareacceleration\": true, \"shadow_elevation\": 120, "
		"\"drag_type\": \"text\", \"shadow_enable\": true }";
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<UnitTestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    ret = InteractionManager::GetInstance()->SetDragWindowVisible(true);
    EXPECT_EQ(ret, RET_OK);
    SimulateMovePointerEvent({ DRAG_SRC_X, DRAG_SRC_Y }, { DRAG_DST_X, DRAG_DST_Y },
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, true);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
    InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: InteractionManagerTest_StartDrag_ShadowColor
 * @tc.desc: Check drag shadow color
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_StartDrag_ShadowColor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
        FI_HILOGD("Param displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    SimulateDownPointerEvent(
        { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID);
    std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragData);
    dragData->filterInfo = "{ \"dip_scale\": 3.5, \"drag_shadow_offsetX\": 30, \"drag_shadow_offsetY\": 30, "
        "\"drag_shadow_argb\": 872415231, \"drag_shadow_path\": \"M 10 10 H 80 V 80 H 10 L 10 10\", "
		"\"shadow_color_strategy\": 0, \"shadow_is_hardwareacceleration\": true, \"shadow_elevation\": 120, "
		"\"drag_type\": \"text\", \"shadow_enable\": true }";
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<UnitTestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    ret = InteractionManager::GetInstance()->SetDragWindowVisible(true);
    EXPECT_EQ(ret, RET_OK);
    SimulateMovePointerEvent({ DRAG_SRC_X, DRAG_SRC_Y }, { DRAG_DST_X, DRAG_DST_Y },
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, true);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
    InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: InteractionManagerTest_StartDrag_ShadowOffset
 * @tc.desc: Check drag shadow offset
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_StartDrag_ShadowOffset, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
        FI_HILOGD("Param displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    SimulateDownPointerEvent(
        { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID);
    std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragData);
    dragData->filterInfo = "{ \"dip_scale\": 3.5, \"drag_shadow_offsetX\": 50, \"drag_shadow_offsetY\": 50, "
        "\"drag_shadow_argb\": 872415231, \"drag_shadow_path\": \"M 10 10 H 80 V 80 H 10 L 10 10\", "
		"\"shadow_color_strategy\": 0, \"shadow_is_hardwareacceleration\": true, \"shadow_elevation\": 120, "
		"\"drag_type\": \"text\", \"shadow_enable\": true }";
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<UnitTestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    ret = InteractionManager::GetInstance()->SetDragWindowVisible(true);
    EXPECT_EQ(ret, RET_OK);
    SimulateMovePointerEvent({ DRAG_SRC_X, DRAG_SRC_Y }, { DRAG_DST_X, DRAG_DST_Y },
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, true);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
    InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: InteractionManagerTest_StartDrag_ShadowCornerRadius
 * @tc.desc: Check drag shadow corner radius
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_StartDrag_ShadowCornerRadius, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
        FI_HILOGD("Param displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    SimulateDownPointerEvent(
        { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID);
    std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragData);
    dragData->filterInfo = "{ \"dip_scale\": 3.5, \"drag_shadow_offsetX\": 30, \"drag_shadow_offsetY\": 30, "
        "\"drag_shadow_argb\": 872415231, \"drag_shadow_path\": \"M 10 10 H 80 V 80 H 10 L 10 10\", "
		"\"shadow_color_strategy\": 0, \"shadow_is_hardwareacceleration\": false, \"shadow_corner\": 120, "
		"\"drag_type\": \"text\", \"shadow_enable\": true }";
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<UnitTestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    ret = InteractionManager::GetInstance()->SetDragWindowVisible(true);
    EXPECT_EQ(ret, RET_OK);
    SimulateMovePointerEvent({ DRAG_SRC_X, DRAG_SRC_Y }, { DRAG_DST_X, DRAG_DST_Y },
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, true);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
    InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: InteractionManagerTest_StartDrag_ShadowPath001
 * @tc.desc: Check drag shadow path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_StartDrag_ShadowPath001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
        FI_HILOGD("Param displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    SimulateDownPointerEvent(
        { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID);
    std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragData);
    dragData->filterInfo = "{ \"dip_scale\": 3.5, \"drag_shadow_offsetX\": 50, \"drag_shadow_offsetY\": 50, "
        "\"drag_shadow_argb\": 872415231, \"drag_shadow_path\": \"M 10 10 H 90 V 90 H 10 L 10 10\", "
		"\"shadow_color_strategy\": 0, \"shadow_is_hardwareacceleration\": true, \"shadow_elevation\": 120, "
		"\"drag_type\": \"text\", \"shadow_enable\": true }";
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<UnitTestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    ret = InteractionManager::GetInstance()->SetDragWindowVisible(true);
    EXPECT_EQ(ret, RET_OK);
    SimulateMovePointerEvent({ DRAG_SRC_X, DRAG_SRC_Y }, { DRAG_DST_X, DRAG_DST_Y },
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, true);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
    InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: InteractionManagerTest_StartDrag_ShadowPath002
 * @tc.desc: Check drag shadow path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_StartDrag_ShadowPath002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
        FI_HILOGD("Param displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    SimulateDownPointerEvent(
        { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID);
    std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragData);
    dragData->filterInfo = "{ \"dip_scale\": 3.5, \"drag_shadow_offsetX\": 50, \"drag_shadow_offsetY\": 50, "
        "\"drag_shadow_argb\": 872415231, "
		"\"shadow_color_strategy\": 0, \"shadow_is_hardwareacceleration\": true, \"shadow_elevation\": 120, "
		"\"drag_type\": \"text\", \"shadow_enable\": true }";
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<UnitTestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    ret = InteractionManager::GetInstance()->SetDragWindowVisible(true);
    EXPECT_EQ(ret, RET_OK);
    SimulateMovePointerEvent({ DRAG_SRC_X, DRAG_SRC_Y }, { DRAG_DST_X, DRAG_DST_Y },
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, true);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
    InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: InteractionManagerTest_StartDrag_NonTextShadow
 * @tc.desc: Check non-text drag shadow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_StartDrag_NonTextShadow, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
        FI_HILOGD("Param displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    SimulateDownPointerEvent(
        { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID);
    std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragData);
    dragData->filterInfo = "{ \"dip_scale\": 3.5, \"drag_shadow_offsetX\": 50, \"drag_shadow_offsetY\": 50, "
        "\"drag_shadow_argb\": 872415231, "
		"\"shadow_color_strategy\": 0, \"shadow_is_hardwareacceleration\": true, \"shadow_elevation\": 120, "
		"\"drag_type\": \"non-text\", \"shadow_enable\": true }";
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<UnitTestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    ret = InteractionManager::GetInstance()->SetDragWindowVisible(true);
    EXPECT_EQ(ret, RET_OK);
    SimulateMovePointerEvent({ DRAG_SRC_X, DRAG_SRC_Y }, { DRAG_DST_X, DRAG_DST_Y },
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, true);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
    InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
    ret = InteractionManager::GetInstance()->EraseMouseIcon();
    EXPECT_NE(ret, RET_OK);
    ret = InteractionManager::GetInstance()->SetMouseDragMonitorState(0);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InteractionManagerTest_SetDragSwitchState
 * @tc.desc: Get drag summarys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_SetDragSwitchState, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<UnitTestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    ret = InteractionManager::GetInstance()->SetDragSwitchState(true, true);
    EXPECT_EQ(ret, RET_OK);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
    InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: InteractionManagerTest_SetDraggableState
 * @tc.desc: Get drag summarys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_SetDraggableState, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<UnitTestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);

    ret = InteractionManager::GetInstance()->SetDraggableState(true);
    EXPECT_EQ(ret, RET_OK);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
    InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: InteractionManagerTest_SetAppDragSwitchState
 * @tc.desc: Get drag summarys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_SetAppDragSwitchState, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<UnitTestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    const std::string pkgName = "testpkgName";
    ret = InteractionManager::GetInstance()->SetAppDragSwitchState(true, pkgName, true);
    EXPECT_EQ(ret, RET_OK);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
    InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
