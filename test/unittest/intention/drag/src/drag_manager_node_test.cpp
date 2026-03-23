/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "drag_manager_node_test.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

void DragManagerNodeTest::SetUpTestCase() {}

void DragManagerNodeTest::SetUp()
{
    context_ = std::make_shared<TestContext>();
    g_context = context_.get();
    g_dragMgr.Init(g_context);
}

void DragManagerNodeTest::TearDown()
{
    g_context = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

/**
 * @tc.name: GetDragSummaryInfoWithFormat
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerNodeTest, GetDragSummaryInfoWithFormat, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = DragTestHelper::CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    dragData.value().summaryFormat = { { "image", { 0, 1 } } };
    dragData.value().summaryTotalSize = 100;
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    DragSummaryInfo dragSummaryInfo;
    ret = InteractionManager::GetInstance()->GetDragSummaryInfo(dragSummaryInfo);
    ASSERT_EQ(ret, RET_OK);
    ASSERT_EQ(dragSummaryInfo.totalSize, 100);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    InteractionManager::GetInstance()->StopDrag(dropResult);
    EXPECT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: GetDragSummaryInfoWithoutStart
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerNodeTest, GetDragSummaryInfoWithoutStart, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragSummaryInfo dragSummaryInfo;
    int32_t ret = InteractionManager::GetInstance()->GetDragSummaryInfo(dragSummaryInfo);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: GetDragSummaryInfoDirectlyWithoutStart
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerNodeTest, GetDragSummaryInfoDirectlyWithoutStart, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragSummaryInfo dragSummaryInfo;
    int32_t ret = g_dragMgr.GetDragSummaryInfo(dragSummaryInfo);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: GetDragSummaryInfoWithStartedState
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerNodeTest, GetDragSummaryInfoWithStartedState, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.dragState_ = DragState::START;
    DragData dragData;
    dragData.summaryFormat = { { "image", { 0, 1 } } };
    DRAG_DATA_MGR.Init(dragData);
    DragSummaryInfo dragSummaryInfo;
    int32_t ret = g_dragMgr.GetDragSummaryInfo(dragSummaryInfo);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragState_ = DragState::STOP;
}

/**
 * @tc.name: GetDragSummaryInfoWithMotionDraggingState
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerNodeTest, GetDragSummaryInfoWithMotionDraggingState, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.dragState_ = DragState::MOTION_DRAGGING;
    DragData dragData;
    dragData.summaryFormat = { { "image", {} } };
    DRAG_DATA_MGR.Init(dragData);
    DragSummaryInfo dragSummaryInfo;
    int32_t ret = g_dragMgr.GetDragSummaryInfo(dragSummaryInfo);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragState_ = DragState::STOP;
}

/**
 * @tc.name: PrintDragDataWithDetailedSummary
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerNodeTest, PrintDragDataWithDetailedSummary, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragData dragData;
    const std::string udType = "general.message";
    constexpr int64_t recordSize = 20;
    std::map<std::string, int64_t> summarys = { { udType, recordSize } };
    dragData.dragNum = 1;
    dragData.detailedSummarys = summarys;
    dragData.summaryFormat = { { "image", { 0, 1 } } };
    g_dragMgr.PrintDragData(dragData, "");
    DRAG_DATA_MGR.Init(dragData);
    DragData dragDataTest = DRAG_DATA_MGR.GetDragData();
    ASSERT_EQ(dragData.dragNum, dragDataTest.dragNum);
}

/**
 * @tc.name: PrintDragDataWithEmptyFormat
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerNodeTest, PrintDragDataWithEmptyFormat, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragData dragData;
    const std::string udType = "general.message";
    constexpr int64_t recordSize = 20;
    std::map<std::string, int64_t> summarys = { { udType, recordSize } };
    dragData.dragNum = 1;
    dragData.detailedSummarys = summarys;
    dragData.summaryFormat = { { "image", {} } };
    g_dragMgr.PrintDragData(dragData, "");
    DRAG_DATA_MGR.Init(dragData);
    DragData dragDataTest = DRAG_DATA_MGR.GetDragData();
    ASSERT_EQ(dragData.dragNum, dragDataTest.dragNum);
}

/**
 * @tc.name: UpdateDragStylePositionWithRTLLanguages
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerNodeTest, UpdateDragStylePositionWithRTLLanguages, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string persistLanguage = system::GetParameter("persist.global.language", "");
    bool isRTL = g_dragMgr.isRTL_;
    system::SetParameter("persist.global.language", "");
    g_dragMgr.UpdateDragStylePositon();
    EXPECT_EQ(system::GetParameter("persist.global.language", ""), "");
    system::SetParameter("persist.global.language", "ch");
    g_dragMgr.isRTL_ = true;
    g_dragMgr.UpdateDragStylePositon();
    g_dragMgr.isRTL_ = false;
    g_dragMgr.UpdateDragStylePositon();
    EXPECT_EQ(system::GetParameter("persist.global.language", ""), "ch");
    system::SetParameter("persist.global.language", "ar");
    g_dragMgr.isRTL_ = false;
    g_dragMgr.UpdateDragStylePositon();
    g_dragMgr.isRTL_ = true;
    g_dragMgr.UpdateDragStylePositon();
    EXPECT_EQ(system::GetParameter("persist.global.language", ""), "ar");
    system::SetParameter("persist.global.language", "fa");
    g_dragMgr.isRTL_ = false;
    g_dragMgr.UpdateDragStylePositon();
    g_dragMgr.isRTL_ = true;
    g_dragMgr.UpdateDragStylePositon();
    EXPECT_EQ(system::GetParameter("persist.global.language", ""), "fa");
    system::SetParameter("persist.global.language", "ur");
    g_dragMgr.isRTL_ = false;
    g_dragMgr.UpdateDragStylePositon();
    g_dragMgr.isRTL_ = true;
    g_dragMgr.UpdateDragStylePositon();
    EXPECT_EQ(system::GetParameter("persist.global.language", ""), "ur");
    system::SetParameter("persist.global.language", "he");
    g_dragMgr.isRTL_ = false;
    g_dragMgr.UpdateDragStylePositon();
    g_dragMgr.isRTL_ = true;
    g_dragMgr.UpdateDragStylePositon();
    EXPECT_EQ(system::GetParameter("persist.global.language", ""), "he");
    system::SetParameter("persist.global.language", "ug");
    g_dragMgr.isRTL_ = false;
    g_dragMgr.UpdateDragStylePositon();
    g_dragMgr.isRTL_ = true;
    g_dragMgr.UpdateDragStylePositon();
    EXPECT_EQ(system::GetParameter("persist.global.language", ""), "ug");
    g_dragMgr.isRTL_ = isRTL;
    system::SetParameter("persist.global.language", persistLanguage.c_str());
}

/**
 * @tc.name: PerformInternalDropAnimationWithTimer
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerNodeTest, PerformInternalDropAnimationWithTimer, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.ResetAnimationParameter();
    g_dragMgr.ResetDragState();
    std::string animationInfo = "{\"targetPos\": [100, 100]}";
    int32_t ret = InteractionManager::GetInstance()->EnableInternalDropAnimation(animationInfo);
    EXPECT_EQ(ret, RET_OK);
    g_dragMgr.context_ = g_context;
    ret = g_dragMgr.PerformInternalDropAnimation();
    g_dragMgr.context_ = nullptr;
    g_dragMgr.internalDropTimerId_ = 0;
    ret = g_dragMgr.PerformInternalDropAnimation();
    g_dragMgr.context_ = nullptr;
    g_dragMgr.internalDropTimerId_ = -1;
    ret = g_dragMgr.PerformInternalDropAnimation();
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: PerformInternalDropAnimationWithoutContext
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerNodeTest, PerformInternalDropAnimationWithoutContext, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.context_ = g_context;
    g_dragMgr.internalDropTimerId_ = 0;
    g_dragMgr.ResetDragState();
    g_dragMgr.internalDropTimerId_ = -1;
    g_dragMgr.ResetDragState();
    g_dragMgr.context_ = nullptr;
    g_dragMgr.internalDropTimerId_ = 0;
    g_dragMgr.ResetDragState();
    g_dragMgr.context_ = nullptr;
    g_dragMgr.internalDropTimerId_ = -1;
    g_dragMgr.ResetDragState();
    std::string animationInfo = "{\"targetPos\": [100, 100]}";
    int32_t ret = InteractionManager::GetInstance()->EnableInternalDropAnimation(animationInfo);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: UpdateDragNodeBoundsAndFrameWithAnimation
 * @tc.desc: Update drag node bounds and frame
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerNodeTest, UpdateDragNodeBoundsAndFrameWithAnimation, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = DragTestHelper::CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    ASSERT_TRUE(dragData);
    dragData->filterInfo = " { \"enable_animation\": nullptr } ";
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result);
        promiseFlag.set_value(true);
    };
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.UpdateDragNodeBoundsAndFrame(0.0f, 0.0f, 0, 0);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) != std::future_status::timeout);
}

/**
 * @tc.name: UpdateDragNodeBoundsAndFrameWithoutAnimation
 * @tc.desc: Update drag node bounds and frame
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerNodeTest, UpdateDragNodeBoundsAndFrameWithoutAnimation, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = DragTestHelper::CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    ASSERT_TRUE(dragData);
    dragData->filterInfo = " { \"enable_animation\": false } ";
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.allAnimationCnt_ = 100;
    g_dragMgr.dragDrawing_.UpdateDragNodeBoundsAndFrame(0.0f, 0.0f, 0, 0);
    g_dragMgr.dragDrawing_.UpdateDrawingState();
    g_dragMgr.dragDrawing_.DestroyDragWindow();
}

/**
 * @tc.name: UpdateDragNodeBoundsAndFrameWithEnabledAnimation
 * @tc.desc: Update drag node bounds and frame
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerNodeTest, UpdateDragNodeBoundsAndFrameWithEnabledAnimation, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = DragTestHelper::CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    ASSERT_TRUE(dragData);
    dragData->filterInfo = " { \"enable_animation\": true } ";
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.allAnimationCnt_ = 100;
    g_dragMgr.dragDrawing_.UpdateDragNodeBoundsAndFrame(0.0f, 0.0f, 0, 0);
    g_dragMgr.dragDrawing_.UpdateDrawingState();
    g_dragMgr.dragDrawing_.DestroyDragWindow();
}

/**
 * @tc.name: UpdateDragNodeBoundsAndFrameWithChangedPosition
 * @tc.desc: Update drag node bounds and frame
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerNodeTest, UpdateDragNodeBoundsAndFrameWithChangedPosition, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = DragTestHelper::CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    ASSERT_TRUE(dragData);
    dragData->filterInfo = " { \"enable_animation\": true } ";
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.preDragPositionX_ = 100;
    g_dragMgr.dragDrawing_.preDragPositionY_ = 100;
    g_dragMgr.dragDrawing_.UpdateDragNodeBoundsAndFrame(0.0f, 0.0f, 0, 0);
    g_dragMgr.dragDrawing_.UpdateDrawingState();
    g_dragMgr.dragDrawing_.DestroyDragWindow();
}

/**
 * @tc.name: UpdateDragNodeBoundsAndFrameWithOneAnimation
 * @tc.desc: Update drag node bounds and frame
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerNodeTest, UpdateDragNodeBoundsAndFrameWithOneAnimation, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = DragTestHelper::CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    ASSERT_TRUE(dragData);
    dragData->filterInfo = " { \"enable_animation\": true } ";
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.allAnimationCnt_ = 1;
    g_dragMgr.dragDrawing_.preDragPositionX_ = 0;
    g_dragMgr.dragDrawing_.preDragPositionY_ = 0;
    g_dragMgr.dragDrawing_.UpdateDragNodeBoundsAndFrame(0.0f, 0.0f, 0, 0);
    g_dragMgr.dragDrawing_.UpdateDrawingState();
    g_dragMgr.dragDrawing_.DestroyDragWindow();
}

/**
 * @tc.name: UpdateDragNodeBoundsAndFrameWithManyAnimations
 * @tc.desc: Update drag node bounds and frame
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerNodeTest, UpdateDragNodeBoundsAndFrameWithManyAnimations, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = DragTestHelper::CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    ASSERT_TRUE(dragData);
    dragData->filterInfo = " { \"enable_animation\": true } ";
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.allAnimationCnt_ = 100;
    g_dragMgr.dragDrawing_.preDragPositionX_ = 0;
    g_dragMgr.dragDrawing_.preDragPositionY_ = 0;
    g_dragMgr.dragDrawing_.UpdateDragNodeBoundsAndFrame(0.0f, 0.0f, 0, 0);
    g_dragMgr.dragDrawing_.UpdateDrawingState();
    g_dragMgr.dragDrawing_.DestroyDragWindow();
}

/**
 * @tc.name: PrintDragDataWithBothSummaries
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerNodeTest, PrintDragDataWithBothSummaries, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragData dragData;
    const std::string udType = "general.message";
    constexpr int64_t recordSize = 20;
    std::map<std::string, int64_t> summarys = { { udType, recordSize } };
    dragData.detailedSummarys = summarys;
    dragData.summaryFormat = { { "image", { 0, 1 } } };
    dragData.summarys = { { "general.image", 0 }, { "general.video", 1 } };
    dragData.detailedSummarys = { { "general.image", 0 }, { "general.video", 1 } };
    g_dragMgr.PrintDragData(dragData, "");
    ASSERT_TRUE(!dragData.summarys.empty());
    ASSERT_EQ(dragData.summarys.begin()->second, 0);
}

/**
 * @tc.name: PrintDragDataWithMaterialFilter
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerNodeTest, PrintDragDataWithMaterialFilter, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragData dragData;
    const std::string udType = "general.message";
    constexpr int64_t recordSize = 20;
    std::map<std::string, int64_t> summarys = { { udType, recordSize } };
    dragData.detailedSummarys = summarys;
    dragData.summaryFormat = { { "image", { 0, 1 } } };
    dragData.summarys = { { "general.image", 0 }, { "general.video", 1 } };
    dragData.detailedSummarys = { { "general.image", 0 }, { "general.video", 1 } };
    dragData.materialFilter = std::make_shared<Rosen::Filter>();
    g_dragMgr.PrintDragData(dragData, "");
    ASSERT_TRUE(!dragData.summarys.empty());
    ASSERT_EQ(dragData.summarys.begin()->second, 0);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
