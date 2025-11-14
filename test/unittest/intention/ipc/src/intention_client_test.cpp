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

#include "intention_client_test.h"

#include "ipc_skeleton.h"
#include "message_parcel.h"

#include "devicestatus_define.h"
#include "devicestatus_common.h"
#include "i_context.h"


namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
} // namespace

void IntentionClientTest::SetUpTestCase() {}

void IntentionClientTest::SetUp() {}
void IntentionClientTest::TearDown()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

std::optional<DragData> DragClientTest::CreateDragData(int32_t sourceType,
    int32_t pointerId, int32_t dragNum, bool hasCoordinateCorrected, int32_t shadowNum)
{
    CALL_DEBUG_ENTER;
    DragData dragData;
    for (int32_t i = 0; i < shadowNum; i++) {
        std::shared_ptr<Media::PixelMap> pixelMap = CreatePixelMap(PIXEL_MAP_WIDTH, PIXEL_MAP_HEIGHT);
        if (pixelMap == nullptr) {
            FI_HILOGE("pixelMap nullptr");
            return std::nullopt;
        }
        dragData.shadowInfos.push_back({ pixelMap, g_shadowinfo_x, g_shadowinfo_y });
    }
    dragData.buffer = std::vector<uint8_t>(MAX_BUFFER_SIZE, 0);
    dragData.extraInfo = FILTER_INFO;
    dragData.udKey = UD_KEY;
    dragData.sourceType = sourceType;
    dragData.extraInfo = EXTRA_INFO;
    dragData.displayId = DISPLAY_ID;
    dragData.pointerId = pointerId;
    dragData.dragNum = dragNum;
    dragData.displayX = DISPLAY_X;
    dragData.displayY = DISPLAY_Y;
    dragData.hasCoordinateCorrected = hasCoordinateCorrected;
    dragData.hasCanceledAnimation = HAS_CANCELED_ANIMATION;
    return dragData;
}

uint64_t NativeTokenGet()
{
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 0,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = nullptr,
        .acls = nullptr,
        .aplStr = "system_basic",
    };

    infoInstance.processName = " DragServerTest";
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
    return tokenId;
}
class TestStartDragListener : public IStartDragListener {
public:
    explicit TestStartDragListener(std::function<void(const DragNotifyMsg&)> function) : function_(function) { }
    void OnDragEndMessage(const DragNotifyMsg &msg) override
    {
        FI_HILOGD("DisplayX:%{public}d, displayY:%{public}d, targetPid:%{public}d, result:%{public}d",
            msg.displayX, msg.displayY, msg.targetPid, static_cast<int32_t>(msg.result));
        if (function_ != nullptr) {
            function_(msg);
        }
        FI_HILOGD("Test OnDragEndMessage");
    }

    void OnHideIconMessage() override
    {
        FI_HILOGD("Test OnHideIconMessage");
    }
private:
    std::function<void(const DragNotifyMsg&)> function_;
};

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

void DragClientTest::AssignToAnimation(PreviewAnimation &animation)
{
    animation.duration = ANIMATION_DURATION;
    animation.curveName = CURVE_NAME;
    animation.curve = { 0.33, 0, 0.67, 1 };
}


/**
 * @tc.name: IntentionClientTest1
 * @tc.desc: IntentionClientTest1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest1, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    uint64_t displayId = 0;
    uint64_t screenId = 0;
    int32_t ret = env->SetDragWindowScreenId(displayId, screenId);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragClientTest1
 * @tc.desc: DragClient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragClientTest, DragClientTest1, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    bool enable = false;
    bool isJsCaller = false;
    int32_t ret = g_dragClient.SetDragSwitchState(enable, isJsCaller);
    EXPECT_EQ(ret, RET_OK);
}
/**
 * @tc.name: DragClientTest2
 * @tc.desc: DragClient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragClientTest, DragClientTest2, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    bool enable = false;
    std::string pkgName = {"pkg"};
    bool isJsCaller = false;
    int32_t ret = g_dragClient.SetAppDragSwitchState(enable, pkgName, isJsCaller);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragManagerTest12
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest12, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = InteractionManager::GetInstance()->UpdateDragStyle(static_cast<DragCursorStyle>(-1));
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragManagerTest13
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest13, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<Media::PixelMap> pixelMap = CreatePixelMap(PIXEL_MAP_WIDTH, PIXEL_MAP_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);
    ShadowInfo shadowInfo = { pixelMap, 1, 0 };
    int32_t ret = InteractionManager::GetInstance()->UpdateShadowPic(shadowInfo);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragManagerTest14
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest14, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    std::vector<DragCursorStyle> dragCursorStyles = {DragCursorStyle::DEFAULT,
        DragCursorStyle::FORBIDDEN, DragCursorStyle::COPY, DragCursorStyle::MOVE};
    for (const auto& dragCursorStyle : dragCursorStyles) {
        ret = InteractionManager::GetInstance()->UpdateDragStyle(dragCursorStyle);
        ASSERT_EQ(ret, RET_OK);
    }
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: DragManagerTest15
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest15, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: DragManagerTest16
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest16, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    std::string udKey;
    ret = InteractionManager::GetInstance()->GetUdKey(udKey);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}


/**
 * @tc.name: IntentionClientTest2
 * @tc.desc: IntentionClientTest2
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest2, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    uint64_t displayId = UINT64_MAX;
    uint64_t screenId = 0;
    int32_t ret = env->SetDragWindowScreenId(displayId, screenId);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest3
 * @tc.desc: IntentionClientTest3
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest3, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    uint64_t displayId = 0;
    uint64_t screenId = UINT64_MAX;
    int32_t ret = env->SetDragWindowScreenId(displayId, screenId);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest4
 * @tc.desc: IntentionClientTest4
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest4, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    uint64_t displayId = UINT64_MAX;
    uint64_t screenId = UINT64_MAX;
    int32_t ret = env->SetDragWindowScreenId(displayId, screenId);
    ASSERT_EQ(ret, RET_OK);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
