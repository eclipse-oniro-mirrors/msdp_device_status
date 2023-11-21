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
#include "pointer_event.h"
#include "securec.h"

#include "coordination_message.h"
#include "devicestatus_define.h"
#include "devicestatus_errors.h"
#include "interaction_manager.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL { LOG_CORE, MSDP_DOMAIN_ID, "InteractionManagerTest" };
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
constexpr int32_t TIME_WAIT_FOR_INJECT_MS { 80 };
constexpr int32_t TIME_WAIT_FOR_TOUCH_DOWN_MS { 1000 };
constexpr int32_t PROMISE_WAIT_SPAN_MS { 2000 };
constexpr int32_t TIME_WAIT_FOR_NOTIFY_LINSTER { 100 };
constexpr int32_t TEST_PIXEL_MAP_WIDTH { 200 };
constexpr int32_t TEST_PIXEL_MAP_HEIGHT { 200 };
constexpr int32_t MAX_PIXEL_MAP_WIDTH { 600 };
constexpr int32_t MAX_PIXEL_MAP_HEIGHT { 600 };
constexpr int32_t MOUSE_POINTER_ID { 0 };
constexpr int32_t TOUCH_POINTER_ID { 1 };
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
constexpr int32_t FOREGROUND_COLOR_IN { 0x00FF0000 };
constexpr int32_t FOREGROUND_COLOR_OUT { 0x00000000 };
constexpr int32_t RADIUS_IN { 42 };
constexpr int32_t RADIUS_OUT { 42 };
constexpr int32_t ALPHA_IN { 51 };
constexpr int32_t ALPHA_OUT { 0 };
constexpr int64_t DOWN_TIME { 1 };
const std::string UD_KEY { "Unified data key" };
const std::string EXTRA_INFO { "{ \"drag_allow_distributed\" : false }" };
const std::string SYSTEM_CORE { "system_core" };
const std::string SYSTEM_BASIC { "system_basic" };
int32_t g_deviceMouseId { -1 };
int32_t g_deviceTouchId { -1 };
int32_t g_screenWidth { 720 };
int32_t g_screenHeight { 1280 };
uint64_t g_tokenID { 0 };
const char *g_cores[] = { "ohos.permission.INPUT_MONITORING" };
const char *g_basics[] = { "ohos.permission.COOPERATE_MANAGER" };
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
    explicit SubscriptListenerTest(const std::string& name) : moduleName_(name)
    {
        futureFlag_ = promiseFlag_.get_future();
    }
    void OnMessage(DragCursorStyle style) override
    {
        if (style != dragStyle_) {
            promiseFlag_.set_value(true);
        }
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

public:
    std::promise<bool> promiseFlag_;
    std::future<bool> futureFlag_;

private:
    DragCursorStyle dragStyle_ { DragCursorStyle::DEFAULT };
    std::string moduleName_;
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

void InteractionManagerTest::SetUp() {}

void InteractionManagerTest::TearDown()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
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
    uint32_t *colors = new (std::nothrow) uint32_t[colorLen];
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
    DragData dragData;
    dragData.shadowInfo.pixelMap = pixelMap;
    dragData.shadowInfo.x = 0;
    dragData.shadowInfo.y = 0;
    dragData.buffer = std::vector<uint8_t>(MAX_BUFFER_SIZE, 0);
    dragData.udKey = UD_KEY;
    dragData.sourceType = sourceType;
    dragData.pointerId = pointerId;
    dragData.dragNum = DRAG_NUM;
    dragData.displayX = location.first;
    dragData.displayY = location.second;
    dragData.displayId = displayId;
    dragData.hasCanceledAnimation = HAS_CANCELED_ANIMATION;
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
    std::shared_ptr<MMI::PointerEvent> pointerEvent =
        SetupPointerEvent(location, MMI::PointerEvent::POINTER_ACTION_DOWN, sourceType, pointerId, true);
    CHKPV(pointerEvent);
    FI_HILOGD("TEST:sourceType:%{public}d, pointerId:%{public}d, pointerAction:%{public}d",
        pointerEvent->GetSourceType(), pointerEvent->GetPointerId(), pointerEvent->GetPointerAction());
    MMI::InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
}

void InteractionManagerTest::SimulateUpPointerEvent(const std::pair<int32_t, int32_t> &location, int32_t sourceType,
    int32_t pointerId)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<MMI::PointerEvent> pointerEvent = SetupPointerEvent(location,
        MMI::PointerEvent::POINTER_ACTION_UP, sourceType, pointerId, false);
    CHKPV(pointerEvent);
    FI_HILOGD("TEST:sourceType:%{public}d, pointerId:%{public}d, pointerAction:%{public}d",
        pointerEvent->GetSourceType(), pointerEvent->GetPointerId(), pointerEvent->GetPointerAction());
    MMI::InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
}

void InteractionManagerTest::SimulateMovePointerEvent(const std::pair<int32_t, int32_t> &srcLocation,
    const std::pair<int32_t, int32_t> &dstLocation, int32_t sourceType, int32_t pointerId, bool isPressed)
{
    CALL_DEBUG_ENTER;
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
    FI_HILOGD("PixelAlphaType:%{public}d, PixelFormat:%{public}d, PixelAllocatorType:%{public}d,"
        " PixelWidth:%{public}d, PixelHeight:%{public}d, shadowX:%{public}d, shadowY:%{public}d,"
        " sourceType:%{public}d, pointerId:%{public}d, displayId:%{public}d, displayX:%{public}d,"
        " displayY:%{public}d, dragNum:%{public}d, hasCanceledAnimation:%{public}d, udKey:%{public}s",
        static_cast<int32_t>(dragData.shadowInfo.pixelMap->GetAlphaType()),
        static_cast<int32_t>(dragData.shadowInfo.pixelMap->GetPixelFormat()),
        static_cast<int32_t>(dragData.shadowInfo.pixelMap->GetAllocatorType()),
        dragData.shadowInfo.pixelMap->GetWidth(), dragData.shadowInfo.pixelMap->GetHeight(),
        dragData.shadowInfo.x, dragData.shadowInfo.y, dragData.sourceType, dragData.pointerId,
        dragData.displayId, dragData.displayX, dragData.displayY, dragData.dragNum, dragData.hasCanceledAnimation,
        dragData.udKey.substr(0, SUBSTR_UDKEY_LEN).c_str());
}

void InteractionManagerTest::SetupKeyEvent(
    int32_t action, int32_t key, bool isPressed)
{
    CALL_DEBUG_ENTER;
    CHKPP(g_keyEvent);
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
    SetupKeyEvent(MMI::KeyEvent::KEY_ACTION_DOWN, key, true);
    FI_HILOGD("TEST:keyCode:%{public}d, keyAction: KEY_ACTION_DOWN", key);
    MMI::InputManager::GetInstance()->SimulateInputEvent(g_keyEvent);
}

void InteractionManagerTest::SimulateUpKeyEvent(int32_t key)
{
    CALL_DEBUG_ENTER;
    SetupKeyEvent(MMI::KeyEvent::KEY_ACTION_UP, key, false);
    FI_HILOGD("TEST:keyCode:%{public}d, keyAction: KEY_ACTION_UP", key);
    MMI::InputManager::GetInstance()->SimulateInputEvent(g_keyEvent);
}

void InteractionManagerTest::PrintDragAction(DragAction dragAction)
{
    switch (dragAction) {
        case DragAction::MOVE:
            FI_HILOGD("drag action: MOVE");
            break;
        case DragAction::COPY:
            FI_HILOGD("drag action: COPY");
            break;
        default:
            FI_HILOGD("drag action: UNKNOWN");
            break;
    }
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
                pointerAction == MMI::PointerEvent::POINTER_ACTION_PULL_UP);
    ASSERT_TRUE(!pointerEvent->GetBuffer().empty());
    MMI::PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem);
    if (callback_ != nullptr && pointerItem.GetDisplayX() == DRAG_DST_X && pointerItem.GetDisplayY() == DRAG_DST_Y) {
        callback_();
    }
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
    bool isCheckPermission = true;
    int32_t ret = InteractionManager::GetInstance()->RegisterCoordinationListener(consumer, isCheckPermission);
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
    bool isCheckPermission = true;
    int32_t ret = InteractionManager::GetInstance()->RegisterCoordinationListener(consumer, isCheckPermission);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    ASSERT_EQ(ret, RET_OK);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COORDINATION
    ret = InteractionManager::GetInstance()->UnregisterCoordinationListener(consumer, isCheckPermission);
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
    bool isCheckPermission = true;
    int32_t ret = InteractionManager::GetInstance()->UnregisterCoordinationListener(consumer, isCheckPermission);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    ASSERT_EQ(ret, RET_OK);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COORDINATION
    RemovePermission();
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
    auto fun = [&promiseFlag](std::string listener, CoordinationMessage coordinationMessages) {
        FI_HILOGD("Prepare coordination success, listener:%{public}s", listener.c_str());
        promiseFlag.set_value(true);
    };
    bool isCheckPermission = true;
    int32_t ret = InteractionManager::GetInstance()->PrepareCoordination(fun, isCheckPermission);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    ASSERT_EQ(ret, RET_OK);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) != std::future_status::timeout);
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
    auto fun = [&promiseFlag](std::string listener, CoordinationMessage coordinationMessages) {
        FI_HILOGD("Prepare coordination success, listener:%{public}s", listener.c_str());
        promiseFlag.set_value(true);
    };
    bool isCheckPermission = true;
    int32_t ret = InteractionManager::GetInstance()->UnprepareCoordination(fun, isCheckPermission);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    ASSERT_EQ(ret, RET_OK);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) != std::future_status::timeout);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COORDINATION
    RemovePermission();
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
    auto fun = [](std::string listener, CoordinationMessage coordinationMessages) {
        FI_HILOGD("Start coordination success");
        (void) listener;
    };
    bool isCheckPermission = true;
    int32_t ret = InteractionManager::GetInstance()->ActivateCoordination(remoteNetworkId, startDeviceId,
        fun, isCheckPermission);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    ASSERT_NE(ret, RET_OK);
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
    auto fun = [](std::string listener, CoordinationMessage coordinationMessages) {
        FI_HILOGD("Stop coordination success");
        (void) listener;
    };
    bool isCheckPermission = true;
    int32_t ret = InteractionManager::GetInstance()->DeactivateCoordination(false, fun, isCheckPermission);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    ASSERT_NE(ret, RET_OK);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
    ret = InteractionManager::GetInstance()->DeactivateCoordination(true, fun, isCheckPermission);
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
    bool isCheckPermission = true;
    int32_t ret = InteractionManager::GetInstance()->GetCoordinationState(networkId, fun, isCheckPermission);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    ASSERT_NE(ret, RET_OK);
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
    bool isCheckPermission = true;
    int32_t ret = InteractionManager::GetInstance()->GetCoordinationState(networkId, fun, isCheckPermission);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    ASSERT_EQ(ret, RET_OK);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) != std::future_status::timeout);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COORDINATION
    RemovePermission();
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
        ret = InteractionManager::GetInstance()->StartDrag(dragData.value(), callback);
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
        ret = InteractionManager::GetInstance()->StartDrag(dragData.value(), callback);
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
        ret = InteractionManager::GetInstance()->StartDrag(dragData.value(), callback);
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
        SimulateDownPointerEvent(
            { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID);
        std::optional<DragData> dragData = CreateDragData({ MAX_PIXEL_MAP_WIDTH, MAX_PIXEL_MAP_HEIGHT },
            MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
        ASSERT_TRUE(dragData);
        ret = InteractionManager::GetInstance()->StartDrag(dragData.value(), callback);
        ASSERT_EQ(ret, RET_OK);
        SimulateMovePointerEvent({ DRAG_SRC_X, DRAG_SRC_Y }, { DRAG_DST_X, DRAG_DST_Y },
            MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, true);
        DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
        SimulateUpPointerEvent(
            { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID);
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
        SimulateDownPointerEvent(
            { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID);
        ret = InteractionManager::GetInstance()->StartDrag(dragData.value(), callback);
        ASSERT_EQ(ret, RET_OK);
        ret = InteractionManager::GetInstance()->SetDragWindowVisible(true);
        ASSERT_EQ(ret, RET_OK);
        DragCursorStyle style = DragCursorStyle::DEFAULT;
        ret = InteractionManager::GetInstance()->UpdateDragStyle(style);
        ASSERT_EQ(ret, RET_OK);
        SimulateMovePointerEvent({ DRAG_SRC_X, DRAG_SRC_Y }, { DRAG_DST_X, DRAG_DST_Y },
            MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, true);
        EXPECT_TRUE(listener->futureFlag_.wait_for(std::chrono::milliseconds(TIME_WAIT_FOR_NOTIFY_LINSTER)) !=
            std::future_status::timeout);
        DragCursorStyle recvStyle = listener->GetDragStyle();
        FI_HILOGD("Recived style:%{public}d, expected style:%{public}d", static_cast<int32_t>(recvStyle),
            static_cast<int32_t>(style));
        DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
        SimulateUpPointerEvent(
            { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID);
        InteractionManager::GetInstance()->StopDrag(dropResult);
        ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
            std::future_status::timeout);
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
        int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(), callback);
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

        dragData->shadowInfo.pixelMap = nullptr;
        ret = InteractionManager::GetInstance()->StartDrag(dragData.value(), callback);
        ASSERT_EQ(ret, RET_ERR);
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
        int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(), callback);
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
        int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(), callback);
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
        std::future<bool> futureFlag = promiseFlag.get_future();
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
        int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(), callback);
        ASSERT_EQ(ret, RET_OK);
        DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
        InteractionManager::GetInstance()->StopDrag(dropResult);
        ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
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
        int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(), callback);
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
        int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(), callback);
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
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    if (g_deviceTouchId < 0) {
        ASSERT_TRUE(g_deviceTouchId < 0);
    } else {
        auto callback = [](const DragNotifyMsg& notifyMessage) {
            FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
                notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        };
        SimulateDownPointerEvent(
            { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_TOUCH_DOWN_MS));
        std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
            MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
        ASSERT_TRUE(dragData);
        int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(), callback);
        ASSERT_EQ(ret, RET_OK);
        std::promise<bool> promiseEventFlag;
        std::future<bool> futureEventFlag = promiseEventFlag.get_future();
        auto callbackPtr = std::make_shared<InputEventCallbackTest>(
            [&promiseEventFlag]{promiseEventFlag.set_value(true);});
        int32_t monitorId = TestAddMonitor(callbackPtr);
        SimulateMovePointerEvent({ DRAG_SRC_X, DRAG_SRC_Y }, { DRAG_DST_X, DRAG_DST_Y },
            MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, true);
        ASSERT_TRUE(futureEventFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
            std::future_status::timeout);
        TestRemoveMonitor(monitorId);
        DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
        ret = InteractionManager::GetInstance()->StopDrag(dropResult);
        ASSERT_EQ(ret, RET_OK);
    }
    RemovePermission();
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
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    if (g_deviceMouseId < 0) {
        ASSERT_TRUE(g_deviceMouseId < 0);
    } else {
        auto callback = [](const DragNotifyMsg& notifyMessage) {
            FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
                notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        };
        SimulateDownPointerEvent(
            { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_MOUSE, 0);
        std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
            MMI::PointerEvent::SOURCE_TYPE_MOUSE, 0, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
        ASSERT_TRUE(dragData);
        int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(), callback);
        ASSERT_EQ(ret, RET_OK);
        std::promise<bool> promiseEventFlag;
        std::future<bool> futureEventFlag = promiseEventFlag.get_future();
        auto callbackPtr = std::make_shared<InputEventCallbackTest>(
            [&promiseEventFlag]{promiseEventFlag.set_value(true);});
        int32_t monitorId = TestAddMonitor(callbackPtr);
        SimulateMovePointerEvent({ DRAG_SRC_X, DRAG_SRC_Y }, { DRAG_DST_X, DRAG_DST_Y },
            MMI::PointerEvent::SOURCE_TYPE_MOUSE, TOUCH_POINTER_ID, true);
        ASSERT_TRUE(futureEventFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
            std::future_status::timeout);
        TestRemoveMonitor(monitorId);
        DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
        ret = InteractionManager::GetInstance()->StopDrag(dropResult);
        ASSERT_EQ(ret, RET_OK);
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
    std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(), callback);
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
        int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(), callback);
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
        int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(), callback);
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
        int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(), callback);
        ASSERT_EQ(ret, RET_OK);

        DragData replyDragData;
        ret = InteractionManager::GetInstance()->GetDragData(replyDragData);
        ASSERT_EQ(ret, RET_OK);
        ASSERT_NE(replyDragData.shadowInfo.pixelMap, nullptr);
        ASSERT_EQ(replyDragData.shadowInfo.pixelMap->GetWidth(), TEST_PIXEL_MAP_WIDTH);
        ASSERT_EQ(replyDragData.shadowInfo.pixelMap->GetHeight(), TEST_PIXEL_MAP_HEIGHT);
        ASSERT_EQ(dragData->udKey, replyDragData.udKey);
        ASSERT_EQ(dragData->shadowInfo.x, replyDragData.shadowInfo.x);
        ASSERT_EQ(dragData->shadowInfo.y, replyDragData.shadowInfo.y);
        ASSERT_EQ(dragData->sourceType, replyDragData.sourceType);
        ASSERT_EQ(dragData->pointerId, replyDragData.pointerId);
        ASSERT_EQ(dragData->dragNum, replyDragData.dragNum);
        ASSERT_EQ(dragData->displayX, replyDragData.displayX);
        ASSERT_EQ(dragData->displayY, replyDragData.displayY);
        ASSERT_EQ(dragData->displayId, replyDragData.displayId);
        ASSERT_EQ(dragData->hasCanceledAnimation, replyDragData.hasCanceledAnimation);
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
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(), callback);
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
    sptr<Rosen::Display> display = Rosen::DisplayManager::GetInstance().GetDisplayById(0);
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
    ret = InteractionManager::GetInstance()->RemoveHotAreaListener(listener);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    ASSERT_EQ(ret, RET_OK);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COORDINATION
    RemovePermission();
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
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(), callback);
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
 * @tc.name: InteractionManagerTest_UpdateDragItemStyle
 * @tc.desc: Update drag item style
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, InteractionManagerTest_UpdateDragItemStyle, TestSize.Level1)
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
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(), callback);
    ASSERT_EQ(ret, RET_OK);
    ret = InteractionManager::GetInstance()->SetDragWindowVisible(true);
    EXPECT_EQ(ret, RET_OK);
    std::pair<int32_t, int32_t> enterPos { 500, 50 };
    std::pair<int32_t, int32_t> leavePos { 500, 200 };
    SimulateMovePointerEvent({ DRAG_SRC_X, DRAG_SRC_Y }, { enterPos.first, enterPos.second },
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, true);
    ret = InteractionManager::GetInstance()->UpdateDragItemStyle({ FOREGROUND_COLOR_IN, RADIUS_IN, ALPHA_IN });
    EXPECT_EQ(ret, RET_OK);
    SimulateMovePointerEvent({ enterPos.first, enterPos.second }, { leavePos.first, leavePos.second },
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, true);
    ret = InteractionManager::GetInstance()->UpdateDragItemStyle({ FOREGROUND_COLOR_OUT, RADIUS_OUT, ALPHA_OUT });
    EXPECT_EQ(ret, RET_OK);
    SimulateMovePointerEvent({ leavePos.first, leavePos.second }, { DRAG_DST_X, DRAG_DST_Y },
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID, true);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
    InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/*
 * @tc.name: InteractionManagerTest_EnterTextEditorArea
 * @tc.desc: pixelMap 8dp bit movement effect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InteractionManagerTest, EnterTextEditorArea, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = InteractionManager::GetInstance()->EnterTextEditorArea(true);
    FI_HILOGD("ret:%{public}d", ret);
    ASSERT_EQ(ret, RET_OK);
    ret = InteractionManager::GetInstance()->EnterTextEditorArea(false);
    FI_HILOGD("ret:%{public}d", ret);
    ASSERT_EQ(ret, RET_ERR);
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
        dragData->extraInfo = EXTRA_INFO;
        std::promise<bool> promiseFlag;
        std::future<bool> futureFlag = promiseFlag.get_future();
        auto callback = [&promiseFlag](const DragNotifyMsg& notifyMessage) {
            FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
                notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
            promiseFlag.set_value(true);
        };
        int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(), callback);
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
    SimulateDownPointerEvent(
        { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID);
    std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(), callback);
    ASSERT_EQ(ret, RET_OK);
    DragAction dragAction { DragAction::INVALID };
    ret = InteractionManager::GetInstance()->GetDragAction(dragAction);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(dragAction, DragAction::MOVE);
    PrintDragAction(dragAction);
    SimulateUpPointerEvent(
        { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID);
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
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    SimulateDownPointerEvent(
        { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID);
    std::optional<DragData> dragData = CreateDragData({ TEST_PIXEL_MAP_WIDTH, TEST_PIXEL_MAP_HEIGHT },
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, MOUSE_POINTER_ID, DISPLAY_ID, { DRAG_SRC_X, DRAG_SRC_Y });
    ASSERT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(), callback);
    ASSERT_EQ(ret, RET_OK);
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
    SimulateUpPointerEvent(
        { DRAG_SRC_X, DRAG_SRC_Y }, MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, TOUCH_POINTER_ID);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
    InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
    ret = InteractionManager::GetInstance()->GetDragAction(dragAction);
    EXPECT_EQ(ret, RET_ERR);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
