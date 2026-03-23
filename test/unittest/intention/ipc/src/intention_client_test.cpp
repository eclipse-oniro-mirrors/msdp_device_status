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
#include "iremote_on_screen_callback.h"

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

class IRemoteOnScreenCallbackTest : public OnScreen::IRemoteOnScreenCallback {
public:
    void OnScreenChange(const std::string &changeInfo) override{};
    void OnScreenAwareness(const OnScreen::OnscreenAwarenessInfo &info) override{};
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

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

/**
 * @tc.name: IntentionClientTest5
 * @tc.desc: IntentionClientTest5
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest5, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    OnScreen::AwarenessCap cap;
    sptr<IRemoteOnScreenCallbackTest> callback = new (std::nothrow) IRemoteOnScreenCallbackTest();
    EXPECT_NE(callback, nullptr);
    OnScreen::AwarenessOptions option;
    int32_t ret = env->RegisterAwarenessCallback(cap, callback, option);
    ASSERT_NE(ret, RET_OK);
}
 
/**
 * @tc.name: IntentionClientTest6
 * @tc.desc: IntentionClientTest6
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest6, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    OnScreen::AwarenessCap cap;
    sptr<IRemoteOnScreenCallbackTest> callback = new (std::nothrow) IRemoteOnScreenCallbackTest();
    EXPECT_NE(callback, nullptr);
    int32_t ret = env->UnregisterAwarenessCallback(cap, callback);
    ASSERT_NE(ret, RET_OK);
}
 
/**
 * @tc.name: IntentionClientTest7
 * @tc.desc: IntentionClientTest7
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest7, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    OnScreen::AwarenessCap cap;
    OnScreen::AwarenessOptions option;
    OnScreen::OnscreenAwarenessInfo info;
    int32_t ret = env->Trigger(cap, option, info);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_StartDrag_001
 * @tc.desc: Test StartDrag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_StartDrag_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    DragData dragData;
    int32_t ret = env->StartDrag(dragData);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_StopDrag_001
 * @tc.desc: Test StopDrag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_StopDrag_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    DragDropResult dropResult;
    int32_t ret = env->StopDrag(dropResult);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_EnableInternalDropAnimation_001
 * @tc.desc: Test EnableInternalDropAnimation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_EnableInternalDropAnimation_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    std::string animationInfo = "test";
    int32_t ret = env->EnableInternalDropAnimation(animationInfo);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_AddDraglistener_001
 * @tc.desc: Test AddDraglistener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_AddDraglistener_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    int32_t ret = env->AddDraglistener(false);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_RemoveDraglistener_001
 * @tc.desc: Test RemoveDraglistener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_RemoveDraglistener_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    int32_t ret = env->RemoveDraglistener(false);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_AddSubscriptListener_001
 * @tc.desc: Test AddSubscriptListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_AddSubscriptListener_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    int32_t ret = env->AddSubscriptListener();
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_RemoveSubscriptListener_001
 * @tc.desc: Test RemoveSubscriptListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_RemoveSubscriptListener_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    int32_t ret = env->RemoveSubscriptListener();
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_SetDragWindowVisible_001
 * @tc.desc: Test SetDragWindowVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_SetDragWindowVisible_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    int32_t ret = env->SetDragWindowVisible(true, false, nullptr);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_UpdateDragStyle_001
 * @tc.desc: Test UpdateDragStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_UpdateDragStyle_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    int32_t ret = env->UpdateDragStyle(DragCursorStyle::DEFAULT, 0);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_UpdateShadowPic_001
 * @tc.desc: Test UpdateShadowPic
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_UpdateShadowPic_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    ShadowInfo shadowInfo;
    int32_t ret = env->UpdateShadowPic(shadowInfo);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_GetDragTargetPid_001
 * @tc.desc: Test GetDragTargetPid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_GetDragTargetPid_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    int32_t targetPid = -1;
    int32_t ret = env->GetDragTargetPid(targetPid);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_GetUdKey_001
 * @tc.desc: Test GetUdKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_GetUdKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    std::string udKey;
    int32_t ret = env->GetUdKey(udKey);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_GetShadowOffset_001
 * @tc.desc: Test GetShadowOffset
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_GetShadowOffset_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    ShadowOffset shadowOffset;
    int32_t ret = env->GetShadowOffset(shadowOffset);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_GetDragData_001
 * @tc.desc: Test GetDragData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_GetDragData_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    DragData dragData;
    int32_t ret = env->GetDragData(dragData);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_UpdatePreviewStyle_001
 * @tc.desc: Test UpdatePreviewStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_UpdatePreviewStyle_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    PreviewStyle previewStyle;
    int32_t ret = env->UpdatePreviewStyle(previewStyle);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_UpdatePreviewStyleWithAnimation_001
 * @tc.desc: Test UpdatePreviewStyleWithAnimation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_UpdatePreviewStyleWithAnimation_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    PreviewStyle previewStyle;
    PreviewAnimation animation;
    int32_t ret = env->UpdatePreviewStyleWithAnimation(previewStyle, animation);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_RotateDragWindowSync_001
 * @tc.desc: Test RotateDragWindowSync
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_RotateDragWindowSync_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    int32_t ret = env->RotateDragWindowSync(nullptr);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_GetDragSummary_001
 * @tc.desc: Test GetDragSummary
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_GetDragSummary_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    std::map<std::string, int64_t> summarys;
    int32_t ret = env->GetDragSummary(summarys, false);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_SetDragSwitchState_001
 * @tc.desc: Test SetDragSwitchState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_SetDragSwitchState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    int32_t ret = env->SetDragSwitchState(true, false);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_SetAppDragSwitchState_001
 * @tc.desc: Test SetAppDragSwitchState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_SetAppDragSwitchState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    int32_t ret = env->SetAppDragSwitchState(true, "test", false);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_GetDragState_001
 * @tc.desc: Test GetDragState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_GetDragState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    DragState dragState = DragState::ERROR;
    int32_t ret = env->GetDragState(dragState);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_EnableUpperCenterMode_001
 * @tc.desc: Test EnableUpperCenterMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_EnableUpperCenterMode_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    int32_t ret = env->EnableUpperCenterMode(true);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_GetDragAction_001
 * @tc.desc: Test GetDragAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_GetDragAction_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    DragAction dragAction = DragAction::INVALID;
    int32_t ret = env->GetDragAction(dragAction);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_GetExtraInfo_001
 * @tc.desc: Test GetExtraInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_GetExtraInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    std::string extraInfo;
    int32_t ret = env->GetExtraInfo(extraInfo);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_AddPrivilege_001
 * @tc.desc: Test AddPrivilege
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_AddPrivilege_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    DragEventData dragEventData;
    int32_t ret = env->AddPrivilege("test", dragEventData);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_EraseMouseIcon_001
 * @tc.desc: Test EraseMouseIcon
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_EraseMouseIcon_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    int32_t ret = env->EraseMouseIcon();
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_SetMouseDragMonitorState_001
 * @tc.desc: Test SetMouseDragMonitorState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_SetMouseDragMonitorState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    int32_t ret = env->SetMouseDragMonitorState(true);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_SetDraggableState_001
 * @tc.desc: Test SetDraggableState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_SetDraggableState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    int32_t ret = env->SetDraggableState(true);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_GetAppDragSwitchState_001
 * @tc.desc: Test GetAppDragSwitchState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_GetAppDragSwitchState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    bool state = false;
    int32_t ret = env->GetAppDragSwitchState(state);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_SetDraggableStateAsync_001
 * @tc.desc: Test SetDraggableStateAsync
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_SetDraggableStateAsync_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    int32_t ret = env->SetDraggableStateAsync(true, 0);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_GetDragBundleInfo_001
 * @tc.desc: Test GetDragBundleInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_GetDragBundleInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    DragBundleInfo dragBundleInfo;
    int32_t ret = env->GetDragBundleInfo(dragBundleInfo);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_IsDragStart_001
 * @tc.desc: Test IsDragStart
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_IsDragStart_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    bool isStart = false;
    int32_t ret = env->IsDragStart(isStart);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: IntentionClientTest_GetDragSummaryInfo_001
 * @tc.desc: Test GetDragSummaryInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionClientTest, IntentionClientTest_GetDragSummaryInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = IntentionClient::GetInstance();
    DragSummaryInfo dragSummaryInfo;
    int32_t ret = env->GetDragSummaryInfo(dragSummaryInfo);
    ASSERT_NE(ret, RET_OK);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
