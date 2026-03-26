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

#include "drag_manager_boundary_test.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

void DragManagerBoundaryTest::SetUpTestCase() {}

void DragManagerBoundaryTest::SetUp()
{
    context_ = std::make_shared<TestContext>();
    g_context = context_.get();
    g_dragMgr.Init(g_context);
}

void DragManagerBoundaryTest::TearDown()
{
    g_context = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

/**
 * @tc.name: StopDragWithoutStart
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerBoundaryTest, StopDragWithoutStart, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    int32_t ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_ERR);
}
/**
 * @tc.name: SetDragWindowVisibleWithoutStart
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerBoundaryTest, SetDragWindowVisibleWithoutStart, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = InteractionManager::GetInstance()->SetDragWindowVisible(true);
    ASSERT_EQ(ret, RET_ERR);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    ret = InteractionManager::GetInstance()->SetDragWindowVisible(false);
    ASSERT_EQ(ret, RET_ERR);
}
/**
 * @tc.name: UpdateDragStyleWithoutStart
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerBoundaryTest, UpdateDragStyleWithoutStart, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = -1;
    std::vector<DragCursorStyle> dragCursorStyles = {DragCursorStyle::FORBIDDEN,
        DragCursorStyle::COPY, DragCursorStyle::MOVE};
    for (const auto& dragCursorStyle : dragCursorStyles) {
        ret = InteractionManager::GetInstance()->UpdateDragStyle(dragCursorStyle);
        ASSERT_EQ(ret, RET_ERR);
    }
}
/**
 * @tc.name: UpdateShadowPicWithoutStart
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerBoundaryTest, UpdateShadowPicWithoutStart, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<Media::PixelMap> pixelMap = DragTestHelper::CreatePixelMap(PIXEL_MAP_WIDTH, PIXEL_MAP_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);
    ShadowInfo shadowInfo = { pixelMap, 0, 0 };
    int32_t ret = InteractionManager::GetInstance()->UpdateShadowPic(shadowInfo);
    ASSERT_EQ(ret, RET_ERR);
}
/**
 * @tc.name: GetDragTargetPidWithoutStart
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerBoundaryTest, GetDragTargetPidWithoutStart, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t pid = InteractionManager::GetInstance()->GetDragTargetPid();
    EXPECT_GT(pid, 0);
}
/**
 * @tc.name: GetUdKeyWithoutStart
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerBoundaryTest, GetUdKeyWithoutStart, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string udKey;
    int32_t ret = InteractionManager::GetInstance()->GetUdKey(udKey);
    ASSERT_EQ(ret, RET_ERR);
}
/**
 * @tc.name: GetShadowOffsetWithoutStart
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerBoundaryTest, GetShadowOffsetWithoutStart, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t offsetX = 0;
    int32_t offsetY = 0;
    int32_t width = 0;
    int32_t height = 0;
    int32_t ret = InteractionManager::GetInstance()->GetShadowOffset(offsetX, offsetY, width, height);
    ASSERT_EQ(ret, RET_ERR);
}
/**
 * @tc.name: GetDragDataWithoutStart
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerBoundaryTest, GetDragDataWithoutStart, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragData replyDragData;
    int32_t ret = InteractionManager::GetInstance()->GetDragData(replyDragData);
    ASSERT_EQ(ret, RET_ERR);
}
/**
 * @tc.name: UpdatePreviewStyleWithoutStart
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerBoundaryTest, UpdatePreviewStyleWithoutStart, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    PreviewStyle previewStyleOut;
    previewStyleOut.types = { PreviewType::FOREGROUND_COLOR };
    previewStyleOut.foregroundColor = FOREGROUND_COLOR_OUT;
    int32_t ret = InteractionManager::GetInstance()->UpdatePreviewStyle(previewStyleOut);
    ASSERT_EQ(ret, RET_ERR);
    PreviewStyle previewStyleIn;
    previewStyleIn.types = { PreviewType::FOREGROUND_COLOR };
    previewStyleIn.foregroundColor = FOREGROUND_COLOR_IN;
    ret = InteractionManager::GetInstance()->UpdatePreviewStyle(previewStyleIn);
    ASSERT_EQ(ret, RET_ERR);
}
/**
 * @tc.name: UpdatePreviewStyleWithAnimationWithoutStart
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerBoundaryTest, UpdatePreviewStyleWithAnimationWithoutStart, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    PreviewStyle previewStyleIn;
    previewStyleIn.types = { PreviewType::FOREGROUND_COLOR };
    previewStyleIn.foregroundColor = FOREGROUND_COLOR_IN;
    PreviewAnimation animationIn;
    DragTestHelper::AssignToAnimation(animationIn);
    int32_t ret = InteractionManager::GetInstance()->UpdatePreviewStyleWithAnimation(previewStyleIn, animationIn);
    ASSERT_EQ(ret, RET_ERR);
    PreviewStyle previewStyleOut;
    previewStyleOut.types = { PreviewType::FOREGROUND_COLOR };
    previewStyleOut.foregroundColor = FOREGROUND_COLOR_OUT;
    PreviewAnimation animationOut;
    DragTestHelper::AssignToAnimation(animationOut);
    ret = InteractionManager::GetInstance()->UpdatePreviewStyleWithAnimation(previewStyleOut, animationOut);
    ASSERT_EQ(ret, RET_ERR);
}
/**
 * @tc.name: EnterTextEditorAreaWithoutStart
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerBoundaryTest, EnterTextEditorAreaWithoutStart, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = InteractionManager::GetInstance()->EnterTextEditorArea(true);
    ASSERT_EQ(ret, RET_ERR);
    ret = InteractionManager::GetInstance()->EnterTextEditorArea(false);
    ASSERT_EQ(ret, RET_ERR);
}
/**
 * @tc.name: GetDragActionWithoutStart
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerBoundaryTest, GetDragActionWithoutStart, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragAction dragAction { DragAction::INVALID };
    int32_t ret = InteractionManager::GetInstance()->GetDragAction(dragAction);
    ASSERT_EQ(ret, RET_ERR);
}
/**
 * @tc.name: GetExtraInfoWithoutStart
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerBoundaryTest, GetExtraInfoWithoutStart, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string extraInfo;
    int32_t ret = InteractionManager::GetInstance()->GetExtraInfo(extraInfo);
    ASSERT_EQ(ret, RET_ERR);
}
/**
 * @tc.name: AddPrivilegeWithoutStart
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerBoundaryTest, AddPrivilegeWithoutStart, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragEventData dragEventData {
        .timestampMs = g_timestamp,
        .coordinateX = g_coordinateX,
        .coordinateY = g_coordinateY,
    };
    int32_t ret = InteractionManager::GetInstance()->AddPrivilege(SIGNATURE, dragEventData);
    ASSERT_EQ(ret, RET_ERR);
}


} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
