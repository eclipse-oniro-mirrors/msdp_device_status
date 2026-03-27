/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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

#include "drag_manager_cross_device_test.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

void DragManagerCrossDeviceTest::SetUpTestCase() {}

void DragManagerCrossDeviceTest::SetUp()
{
    context_ = std::make_shared<TestContext>();
    g_context = context_.get();
    g_dragMgr.Init(g_context);
}

void DragManagerCrossDeviceTest::TearDown()
{
    g_context = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

/**
 * @tc.name: GetUdKeyWithCollaborationServiceEnabled
 * @tc.desc: Get udkey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerCrossDeviceTest, GetUdKeyWithCollaborationServiceEnabled, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = TestHelper::CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    dragData->udKey = "test";
    dragData->summaryTag = "NEED_FETCH";
    int32_t ret = g_dragMgr.InitDataManager(dragData.value());
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    g_dragMgr.dragState_ = DragState::START;
    g_dragMgr.isCrossDragging_ = false;
    g_dragMgr.isCollaborationService_ = true;
    DragSecurityManager::GetInstance().StoreSecurityPid(SECURITY_PID);
    std::string udKey;
    ret = g_dragMgr.GetUdKey(SECURITY_PID, udKey, false);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.lastEventId_ = 0;
    g_dragMgr.UpdateDragStyle(DragCursorStyle::MOVE, 0, 0, 1);
    g_dragMgr.UpdateDragStyle(DragCursorStyle::COPY, 0, 0, 1);
    std::map<std::string, int64_t> summarys;
    DragSummaryInfo dragSummaryInfo;
    ret = g_dragMgr.GetDragSummary(summarys);
    ASSERT_EQ(ret, RET_OK);
    ret = g_dragMgr.GetDragSummaryInfo(dragSummaryInfo);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.isCrossDragging_ = true;
    g_dragMgr.isCollaborationService_ = true;
    ret = g_dragMgr.GetUdKey(SECURITY_PID, udKey, false);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.UpdateDragStyle(DragCursorStyle::MOVE, 0, 0, 1);
    g_dragMgr.UpdateDragStyle(DragCursorStyle::COPY, 0, 0, 1);
    ret = g_dragMgr.GetDragSummary(summarys);
    ASSERT_EQ(ret, RET_OK);
    ret = g_dragMgr.GetDragSummaryInfo(dragSummaryInfo);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragState_ = DragState::STOP;
    g_dragMgr.isCrossDragging_ = false;
    g_dragMgr.isCollaborationService_ = false;
}
/**
 * @tc.name: GetUdKeyWithCrossDragging
 * @tc.desc: Get udkey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerCrossDeviceTest, GetUdKeyWithCrossDragging, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = TestHelper::CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    dragData->udKey = "test";
    dragData->summaryTag = "NEED_FETCH";
    int32_t ret = g_dragMgr.InitDataManager(dragData.value());
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    g_dragMgr.dragState_ = DragState::START;
    g_dragMgr.isCrossDragging_ = true;
    g_dragMgr.isCollaborationService_ = false;
    DragSecurityManager::GetInstance().StoreSecurityPid(SECURITY_PID);
    std::string udKey;
    ret = g_dragMgr.GetUdKey(SECURITY_PID, udKey, false);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.UpdateDragStyle(DragCursorStyle::MOVE, 0, 0, 1);
    g_dragMgr.UpdateDragStyle(DragCursorStyle::COPY, 0, 0, 1);
    std::map<std::string, int64_t> summarys;
    DragSummaryInfo dragSummaryInfo;
    ret = g_dragMgr.GetDragSummary(summarys);
    ASSERT_EQ(ret, RET_OK);
    ret = g_dragMgr.GetDragSummaryInfo(dragSummaryInfo);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.isCrossDragging_ = false;
    g_dragMgr.isCollaborationService_ = false;
    ret = g_dragMgr.GetUdKey(SECURITY_PID, udKey, false);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.UpdateDragStyle(DragCursorStyle::MOVE, 0, 0, 1);
    g_dragMgr.UpdateDragStyle(DragCursorStyle::COPY, 0, 0, 1);
    ret = g_dragMgr.GetDragSummary(summarys);
    ASSERT_EQ(ret, RET_OK);
    ret = g_dragMgr.GetDragSummaryInfo(dragSummaryInfo);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragState_ = DragState::STOP;
}
/**
 * @tc.name: GetUdKeyWithoutCrossDragging
 * @tc.desc: Get udkey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerCrossDeviceTest, GetUdKeyWithoutCrossDragging, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = TestHelper::CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    dragData->udKey = "test";
    int32_t ret = g_dragMgr.InitDataManager(dragData.value());
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    g_dragMgr.dragState_ = DragState::START;
    g_dragMgr.isCrossDragging_ = false;
    g_dragMgr.isCollaborationService_ = true;
    DragSecurityManager::GetInstance().StoreSecurityPid(SECURITY_PID);
    std::string udKey;
    ret = g_dragMgr.GetUdKey(SECURITY_PID, udKey, false);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.lastEventId_ = 0;
    g_dragMgr.UpdateDragStyle(DragCursorStyle::MOVE, 0, 0, 1);
    g_dragMgr.UpdateDragStyle(DragCursorStyle::COPY, 0, 0, 1);
    std::map<std::string, int64_t> summarys;
    DragSummaryInfo dragSummaryInfo;
    ret = g_dragMgr.GetDragSummary(summarys);
    ASSERT_EQ(ret, RET_OK);
    ret = g_dragMgr.GetDragSummaryInfo(dragSummaryInfo);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.isCrossDragging_ = true;
    g_dragMgr.isCollaborationService_ = true;
    ret = g_dragMgr.GetUdKey(SECURITY_PID, udKey, false);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.UpdateDragStyle(DragCursorStyle::MOVE, 0, 0, 1);
    g_dragMgr.UpdateDragStyle(DragCursorStyle::COPY, 0, 0, 1);
    ret = g_dragMgr.GetDragSummary(summarys);
    ASSERT_EQ(ret, RET_OK);
    ret = g_dragMgr.GetDragSummaryInfo(dragSummaryInfo);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragState_ = DragState::STOP;
}
/**
 * @tc.name: GetUdKeyWithoutCollaborationService
 * @tc.desc: Get udkey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerCrossDeviceTest, GetUdKeyWithoutCollaborationService, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = TestHelper::CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    dragData->udKey = "test";
    int32_t ret = g_dragMgr.InitDataManager(dragData.value());
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    g_dragMgr.dragState_ = DragState::START;
    g_dragMgr.isCrossDragging_ = true;
    g_dragMgr.isCollaborationService_ = false;
    DragSecurityManager::GetInstance().StoreSecurityPid(SECURITY_PID);
    std::string udKey;
    ret = g_dragMgr.GetUdKey(SECURITY_PID, udKey, false);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.UpdateDragStyle(DragCursorStyle::MOVE, 0, 0, 1);
    g_dragMgr.UpdateDragStyle(DragCursorStyle::COPY, 0, 0, 1);
    std::map<std::string, int64_t> summarys;
    DragSummaryInfo dragSummaryInfo;
    ret = g_dragMgr.GetDragSummary(summarys);
    ASSERT_EQ(ret, RET_OK);
    ret = g_dragMgr.GetDragSummaryInfo(dragSummaryInfo);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.isCrossDragging_ = false;
    g_dragMgr.isCollaborationService_ = false;
    ret = g_dragMgr.GetUdKey(SECURITY_PID, udKey, false);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.UpdateDragStyle(DragCursorStyle::MOVE, 0, 0, 1);
    g_dragMgr.UpdateDragStyle(DragCursorStyle::COPY, 0, 0, 1);
    ret = g_dragMgr.GetDragSummary(summarys);
    ASSERT_EQ(ret, RET_OK);
    ret = g_dragMgr.GetDragSummaryInfo(dragSummaryInfo);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragState_ = DragState::STOP;
}
/**
 * @tc.name: StartDragWithMaterialFilter
 * @tc.desc: Drag Manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerCrossDeviceTest, StartDragWithMaterialFilter, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = TestHelper::CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    dragData.value().summarys = { { "general.image", 0 }, { "general.video", 1 } };
    dragData.value().detailedSummarys = { { "general.image", 0 }, { "general.video", 1 } };
    dragData.value().isSetMaterialFilter = true;
    std::shared_ptr<Rosen::FilterPara> para = std::make_shared<Rosen::FilterPara>();
    dragData.value().materialFilter = std::make_shared<Rosen::Filter>();
    dragData.value().materialFilter->AddPara(para);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}
/**
 * @tc.name: GetUdKeyWithInvalidSecurityPid
 * @tc.desc: Get udkey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerCrossDeviceTest, GetUdKeyWithInvalidSecurityPid, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = TestHelper::CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    dragData->udKey = "test";
    int32_t ret = g_dragMgr.InitDataManager(dragData.value());
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    g_dragMgr.dragState_ = DragState::START;
    g_dragMgr.isCrossDragging_ = true;
    g_dragMgr.isCollaborationService_ = false;
    DragSecurityManager::GetInstance().StoreSecurityPid(0);
    std::string udKey;
    ret = g_dragMgr.GetUdKey(SECURITY_PID, udKey, false);
    ASSERT_EQ(ret, RET_ERR);
}
/**
 * @tc.name: GetUdKeyWithNeedFetchTag
 * @tc.desc: Get udkey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerCrossDeviceTest, GetUdKeyWithNeedFetchTag, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = TestHelper::CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    dragData->udKey = "test";
    int32_t ret = g_dragMgr.InitDataManager(dragData.value());
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    g_dragMgr.dragState_ = DragState::START;
    g_dragMgr.isCrossDragging_ = true;
    g_dragMgr.isCollaborationService_ = false;
    DragSecurityManager::GetInstance().StoreSecurityPid(SECURITY_PID);
    std::string udKey;
    ret = g_dragMgr.GetUdKey(SECURITY_PID, udKey, true);
    ASSERT_EQ(ret, RET_OK);
}
/**
 * @tc.name: OnDragMoveWithMinActionTime
 * @tc.desc: Drag Manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerCrossDeviceTest, OnDragMoveWithMinActionTime, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = TestHelper::CreateDragData(
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
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int64_t downTime = GetMillisTime();
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    pointerEvent->SetButtonId(MMI::PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetButtonPressed(MMI::PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->SetActionTime(INT64_MIN);
    MMI::PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetDownTime(downTime);
    item.SetPressed(true);
    item.SetRawDx(60);
    item.SetRawDy(60);
    item.SetDisplayX(100);
    item.SetDisplayY(100);
    pointerEvent->AddPointerItem(item);
    g_dragMgr.OnDragMove(pointerEvent);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}
/**
 * @tc.name: OnDragMoveWithMaxActionTime
 * @tc.desc: Drag Manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerCrossDeviceTest, OnDragMoveWithMaxActionTime, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = TestHelper::CreateDragData(
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
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int64_t downTime = GetMillisTime();
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    pointerEvent->SetButtonId(MMI::PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetButtonPressed(MMI::PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->SetActionTime(INT64_MAX);
    MMI::PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetDownTime(downTime);
    item.SetPressed(true);
    item.SetRawDx(60);
    item.SetRawDy(60);
    item.SetDisplayX(100);
    item.SetDisplayY(100);
    pointerEvent->AddPointerItem(item);
    g_dragMgr.OnDragMove(pointerEvent);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}
/**
 * @tc.name: OnDragMoveWithZeroActionTime
 * @tc.desc: Drag Manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerCrossDeviceTest, OnDragMoveWithZeroActionTime, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = TestHelper::CreateDragData(
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
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int64_t downTime = GetMillisTime();
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    pointerEvent->SetButtonId(MMI::PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetButtonPressed(MMI::PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->SetActionTime(0);
    MMI::PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetDownTime(downTime);
    item.SetPressed(true);
    item.SetRawDx(60);
    item.SetRawDy(60);
    item.SetDisplayX(100);
    item.SetDisplayY(100);
    pointerEvent->AddPointerItem(item);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}
/**
 * @tc.name: OnDragMoveWithTouchSource
 * @tc.desc: Drag Manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerCrossDeviceTest, OnDragMoveWithTouchSource, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = TestHelper::CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
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
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int64_t downTime = GetMillisTime();
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    pointerEvent->SetButtonId(MMI::PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetButtonPressed(MMI::PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->SetActionTime(downTime);
    MMI::PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetDownTime(downTime);
    item.SetPressed(true);
    item.SetRawDx(60);
    item.SetRawDy(60);
    item.SetDisplayX(100);
    item.SetDisplayY(100);
    pointerEvent->AddPointerItem(item);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}
/**
 * @tc.name: StopDragWithVariousStates
 * @tc.desc: Drag Manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerCrossDeviceTest, StopDragWithVariousStates, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragDropResult dropResult { DragResult::DRAG_EXCEPTION, HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    g_dragMgr.dragState_ = DragState::START;
    int32_t ret = g_dragMgr.StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragState_ = DragState::START;
    g_dragMgr.isLongPressDrag_ = true;
    ret = g_dragMgr.StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragState_ = DragState::START;
    g_dragMgr.isLongPressDrag_ = true;
    ret = g_dragMgr.StopDrag(dropResult, std::string(), 0);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragState_ = DragState::START;
    g_dragMgr.isLongPressDrag_ = false;
    ret = g_dragMgr.StopDrag(dropResult, std::string(), 0);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.isLongPressDrag_ = false;
    g_dragMgr.dragState_ = DragState::STOP;
}
/**
 * @tc.name: GetPackageNameWithLongPress
 * @tc.desc: Drag Manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerCrossDeviceTest, GetPackageNameWithLongPress, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.isLongPressDrag_ = false;
    std::string packageName = g_dragMgr.GetPackageName(-1);
    ASSERT_EQ(packageName, "Cross-device drag");
    g_dragMgr.isLongPressDrag_ = true;
    packageName = g_dragMgr.GetPackageName(-1);
    ASSERT_EQ(packageName, "Long-press drag");
    packageName = g_dragMgr.GetPackageName(0);
    ASSERT_EQ(packageName, std::string());
    g_dragMgr.context_ = nullptr;
    packageName = g_dragMgr.GetPackageName(0);
    ASSERT_EQ(packageName, std::string());
}
/**
 * @tc.name: GetDragRadarPackageName
 * @tc.desc: Drag Manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerCrossDeviceTest, GetDragRadarPackageName, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.isLongPressDrag_ = false;
    DragRadarPackageName dragRadarPackageName = g_dragMgr.GetDragRadarPackageName(-1, std::string(), std::string());
    ASSERT_EQ(dragRadarPackageName.appCaller, std::string());
    g_dragMgr.isLongPressDrag_ = true;
    dragRadarPackageName = g_dragMgr.GetDragRadarPackageName(-1, std::string(), std::string());
    ASSERT_EQ(dragRadarPackageName.appCaller, std::string());
    g_dragMgr.isLongPressDrag_ = false;
    dragRadarPackageName = g_dragMgr.GetDragRadarPackageName(0, std::string(), std::string());
    ASSERT_EQ(dragRadarPackageName.appCaller, std::string());
    g_dragMgr.isLongPressDrag_ = true;
    dragRadarPackageName = g_dragMgr.GetDragRadarPackageName(0, std::string(), std::string());
    ASSERT_EQ(dragRadarPackageName.appCaller, std::string());
}
/**
 * @tc.name: StartDragWithDisplayId
 * @tc.desc: Drag Manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerCrossDeviceTest, StartDragWithDisplayId, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = TestHelper::CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    g_dragMgr.dragState_ = DragState::STOP;
    int32_t ret = g_dragMgr.StartDrag(dragData.value(), -1, std::string(), false);
    ASSERT_EQ(ret, RET_OK);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = g_dragMgr.StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    ret = g_dragMgr.StartDrag(dragData.value(), -1, std::string(), true);
    ASSERT_EQ(ret, RET_OK);
    ret = g_dragMgr.StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    ret = g_dragMgr.StartDrag(dragData.value(), 0, std::string(), true);
    ASSERT_EQ(ret, RET_OK);
    ret = g_dragMgr.StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    ret = g_dragMgr.StartDrag(dragData.value(), 0, std::string(), false);
    ASSERT_EQ(ret, RET_OK);
    ret = g_dragMgr.StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragState_ = DragState::STOP;
}


} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
