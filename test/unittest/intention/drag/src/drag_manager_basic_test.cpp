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

#include "drag_manager_basic_test.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

void DragManagerBasicTest::SetUpTestCase() {}

void DragManagerBasicTest::SetUp()
{
    context_ = std::make_shared<TestContext>();
    g_context = context_.get();
    g_dragMgr.Init(g_context);
}

void DragManagerBasicTest::TearDown()
{
    g_context = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

/**
 * @tc.name: StartDragWithNullListener
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerBasicTest, StartDragWithNullListener, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = DragTestHelper::CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(), nullptr);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: StartDragWithZeroShadowNum
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerBasicTest, StartDragWithZeroShadowNum, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = DragTestHelper::CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE, false, 0);
    EXPECT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.name: StartDragWithInvalidShadowX
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerBasicTest, StartDragWithInvalidShadowX, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    g_shadowinfo_x = 2;
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = DragTestHelper::CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) != std::future_status::timeout);
}

/**
 * @tc.name: StartDragWithInvalidDragNum
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerBasicTest, StartDragWithInvalidDragNum, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_shadowinfo_x = 0;
    std::promise<bool> promiseFlag;
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = DragTestHelper::CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, -1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: AddRemoveDragListenerWithNull
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerBasicTest, AddRemoveDragListenerWithNull, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = InteractionManager::GetInstance()->AddDraglistener(nullptr);
    ASSERT_EQ(ret, RET_ERR);
    ret = InteractionManager::GetInstance()->RemoveDraglistener(nullptr);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: AddDragListenerSuccessfully
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerBasicTest, AddDragListenerSuccessfully, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<DragListenerTest>(std::string("Draglistener_Mouse"));
    int32_t ret = InteractionManager::GetInstance()->AddDraglistener(listener);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: AddSubscriptListenerWithNull
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerBasicTest, AddSubscriptListenerWithNull, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = InteractionManager::GetInstance()->AddSubscriptListener(nullptr);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: AddSubscriptListenerDuplicate
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerBasicTest, AddSubscriptListenerDuplicate, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<SubscriptListenerTest>("SubscriptListener");
    int32_t ret = InteractionManager::GetInstance()->AddSubscriptListener(listener);
    ASSERT_EQ(ret, RET_OK);
    ret = InteractionManager::GetInstance()->AddSubscriptListener(listener);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: RemoveSubscriptListenerSuccessfully
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerBasicTest, RemoveSubscriptListenerSuccessfully, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<SubscriptListenerTest>("SubscriptListener");
    int32_t ret = InteractionManager::GetInstance()->RemoveSubscriptListener(listener);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: TestStructInequalityOperators
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerBasicTest, RemoveSubscriptListenerWithNull, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = InteractionManager::GetInstance()->RemoveSubscriptListener(nullptr);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: RotateDragWindowWithNull
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerBasicTest, RemoveSubscriptListenerAfterAdd, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = InteractionManager::GetInstance()->RemoveSubscriptListener(nullptr);
    auto listener = std::make_shared<SubscriptListenerTest>("SubscriptListener");
    ret = InteractionManager::GetInstance()->AddSubscriptListener(listener);
    ASSERT_EQ(ret, RET_OK);
    ret = InteractionManager::GetInstance()->RemoveSubscriptListener(nullptr);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: UpdateDragStyleWithInvalidStyle
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerBasicTest, UpdateDragStyleWithInvalidStyle, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = InteractionManager::GetInstance()->UpdateDragStyle(static_cast<DragCursorStyle>(-1));
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: UpdateShadowPicWithError
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerBasicTest, UpdateShadowPicWithError, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<Media::PixelMap> pixelMap = DragTestHelper::CreatePixelMap(PIXEL_MAP_WIDTH, PIXEL_MAP_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);
    ShadowInfo shadowInfo = { pixelMap, 1, 0 };
    int32_t ret = InteractionManager::GetInstance()->UpdateShadowPic(shadowInfo);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: RemoveSubscriptListenerWithNull
 * @tc.desc: Drag Drawingx`
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerBasicTest, TestStructInequalityOperators, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<Media::PixelMap> pixelMap = DragTestHelper::CreatePixelMap(PIXEL_MAP_WIDTH, PIXEL_MAP_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);
    ShadowInfo shadowInfo = { pixelMap, 1, 0 };
    ShadowInfo otherShadowInfo = {};
    EXPECT_TRUE(shadowInfo != otherShadowInfo);
    ShadowOffset shadowOffset {};
    ShadowOffset otherShadowOffset {};
    EXPECT_FALSE(shadowOffset != otherShadowOffset);
    DragData dragData {};
    DragData otherDragData {};
    EXPECT_FALSE(dragData != otherDragData);
    PreviewStyle previewStyle {};
    PreviewStyle otherPreviewStyle {};
    EXPECT_FALSE(previewStyle != otherPreviewStyle);
    Data data {};
    Data otherData {};
    EXPECT_TRUE(data != otherData);
    DragItemStyle dragItemStyle = { 1, 1, 0 };
    DragItemStyle otherDragItemStyle = {};
    EXPECT_TRUE(dragItemStyle != otherDragItemStyle);
}

/**
 * @tc.name: RemoveSubscriptListenerAfterAdd
 * @tc.desc: Drag Drawingx`
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerBasicTest, RotateDragWindowWithNull, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = InteractionManager::GetInstance()->RotateDragWindowSync(nullptr);
    EXPECT_EQ(ret, 5);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS