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
#include "display_change_event_listener_test.h"

#include "devicestatus_define.h"
#include "devicestatus_errors.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
} // namespace

void DisplayChangeEventListenerTest::SetUpTestCase() {}

void DisplayChangeEventListenerTest::SetUp()
{
    context_ = std::make_shared<TestContext>();
    displayListener_ = std::make_shared<DisplayChangeEventListener>(context_.get());
}

void DisplayChangeEventListenerTest::TearDown()
{
    context_ = nullptr;
    displayListener_ = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

/**
 * @tc.name: DisplayChangeEventListenerTest_GetDisplayInfoById_001
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC GetDisplayInfoById
 * @tc.require:
 */
HWTEST_F(DisplayChangeEventListenerTest, DisplayChangeEventListenerTest_GetDisplayInfoById_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(displayListener_, nullptr);
    auto displayInfo = displayListener_->GetDisplayInfoById(0);
    EXPECT_NE(displayInfo, nullptr);
}

/**
 * @tc.name: DisplayChangeEventListenerTest_GetDisplayInfoById_002
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC GetDisplayInfoById
 * @tc.require:
 */
HWTEST_F(DisplayChangeEventListenerTest, DisplayChangeEventListenerTest_GetDisplayInfoById_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(displayListener_, nullptr);
    auto displayInfo = displayListener_->GetDisplayInfoById(-1);
    EXPECT_EQ(displayInfo, nullptr);
}

/**
 * @tc.name: DisplayChangeEventListenerTest_GetDisplayInfo_001
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC GetDisplayInfo
 * @tc.require:
 */
HWTEST_F(DisplayChangeEventListenerTest, DisplayChangeEventListenerTest_GetDisplayInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(displayListener_, nullptr);
    auto displayInfo = displayListener_->GetDisplayInfo(0);
    EXPECT_NE(displayInfo, nullptr);
}

/**
 * @tc.name: DisplayChangeEventListenerTest_GetDisplayInfo_002
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC GetDisplayInfo
 * @tc.require:
 */
HWTEST_F(DisplayChangeEventListenerTest, DisplayChangeEventListenerTest_GetDisplayInfo_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(displayListener_, nullptr);
    auto displayInfo = displayListener_->GetDisplayInfo(-1);
    EXPECT_NE(displayInfo, nullptr);
}

/**
 * @tc.name: DisplayChangeEventListenerTest_OnAttributeChange_001
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC OnAttributeChange
 * @tc.require:
 */
HWTEST_F(DisplayChangeEventListenerTest, DisplayChangeEventListenerTest_OnAttributeChange_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(displayListener_, nullptr);
    displayListener_->RotateDragWindow(0, Rosen::Rotation::ROTATION_90);
    auto displayInfo = displayListener_->GetDisplayInfo(0);
    std::vector<std::string> displayAttributes = {"rotation"};
    displayListener_->OnAttributeChange(0, displayAttributes);
    displayListener_->ProcessDisplayEvent(0);
    EXPECT_NE(displayInfo, nullptr);
}

/**
 * @tc.name: DisplayChangeEventListenerTest_OnAttributeChange_002
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC OnAttributeChange
 * @tc.require:
 */
HWTEST_F(DisplayChangeEventListenerTest, DisplayChangeEventListenerTest_OnAttributeChange_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(displayListener_, nullptr);
    auto displayInfo = displayListener_->GetDisplayInfo(-1);
    std::vector<std::string> displayAttributes = {};
    displayListener_->OnAttributeChange(-1, displayAttributes);
    displayListener_->ProcessDisplayEvent(-1);
    EXPECT_NE(displayInfo, nullptr);
}

/**
 * @tc.name: DisplayChangeEventListenerTest_OnAttributeChange_003
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC OnAttributeChange
 * @tc.require:
 */
HWTEST_F(DisplayChangeEventListenerTest, DisplayChangeEventListenerTest_OnAttributeChange_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(displayListener_, nullptr);
    displayListener_->RotateDragWindow(0, Rosen::Rotation::ROTATION_90);
    auto displayInfo = displayListener_->GetDisplayInfo(0);
    std::vector<std::string> displayAttributes = {"width"};
    displayListener_->OnAttributeChange(0, displayAttributes);
    displayListener_->ProcessDisplayEvent(0);
    EXPECT_NE(displayInfo, nullptr);
}

/**
 * @tc.name: DisplayChangeEventListenerTest_OnAttributeChange_004
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC OnAttributeChange
 * @tc.require:
 */
HWTEST_F(DisplayChangeEventListenerTest, DisplayChangeEventListenerTest_OnAttributeChange_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(displayListener_, nullptr);
    displayListener_->RotateDragWindow(0, Rosen::Rotation::ROTATION_90);
    auto displayInfo = displayListener_->GetDisplayInfo(0);
    std::vector<std::string> displayAttributes = {"height"};
    displayListener_->OnAttributeChange(0, displayAttributes);
    displayListener_->ProcessDisplayEvent(0);
    EXPECT_NE(displayInfo, nullptr);
}

/**
 * @tc.name: DisplayChangeEventListenerTest_OnAttributeChange_005
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC OnAttributeChange
 * @tc.require:
 */
HWTEST_F(DisplayChangeEventListenerTest, DisplayChangeEventListenerTest_OnAttributeChange_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(displayListener_, nullptr);
    displayListener_->RotateDragWindow(0, Rosen::Rotation::ROTATION_90);
    auto displayInfo = displayListener_->GetDisplayInfo(0);
    std::vector<std::string> displayAttributes = {"unknown"};
    displayListener_->OnAttributeChange(0, displayAttributes);
    displayListener_->ProcessDisplayEvent(0);
    EXPECT_NE(displayInfo, nullptr);
}

/**
 * @tc.name: DisplayChangeEventListenerTest_HandleScreenRotation_001
 * @tc.desc: Test HandleScreenRotation does not reset rotation when lastRotation is ROTATION_0
 * @tc.type: FUNC HandleScreenRotation
 * @tc.require:
 */
HWTEST_F(DisplayChangeEventListenerTest, DisplayChangeEventListenerTest_HandleScreenRotation_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(displayListener_, nullptr);
    context_->GetDragManager().SetRotation(0, Rosen::Rotation::ROTATION_90);
    displayListener_->HandleScreenRotation(0, Rosen::Rotation::ROTATION_0);
    auto rotation = context_->GetDragManager().GetRotation(0);
    EXPECT_EQ(rotation, Rosen::Rotation::ROTATION_90);
    context_->GetDragManager().SetRotation(0, Rosen::Rotation::ROTATION_0);
}

/**
 * @tc.name: DisplayChangeEventListenerTest_HandleScreenRotation_002
 * @tc.desc: Test HandleScreenRotation with null context does not crash
 * @tc.type: FUNC HandleScreenRotation
 * @tc.require:
 */
HWTEST_F(DisplayChangeEventListenerTest, DisplayChangeEventListenerTest_HandleScreenRotation_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(displayListener_, nullptr);
    DisplayChangeEventListener listener(nullptr);
    context_->GetDragManager().SetRotation(0, Rosen::Rotation::ROTATION_90);
    listener.HandleScreenRotation(0, Rosen::Rotation::ROTATION_90);
    auto rotation = context_->GetDragManager().GetRotation(0);
    EXPECT_EQ(rotation, Rosen::Rotation::ROTATION_90);
    context_->GetDragManager().SetRotation(0, Rosen::Rotation::ROTATION_0);
}

/**
 * @tc.name: DisplayChangeEventListenerTest_HandleScreenRotation_003
 * @tc.desc: Test HandleScreenRotation resets rotation to ROTATION_0 via SetRotation
 * @tc.type: FUNC HandleScreenRotation
 * @tc.require:
 */
HWTEST_F(DisplayChangeEventListenerTest, DisplayChangeEventListenerTest_HandleScreenRotation_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(displayListener_, nullptr);
    context_->GetDragManager().SetRotation(0, Rosen::Rotation::ROTATION_90);
    displayListener_->HandleScreenRotation(0, Rosen::Rotation::ROTATION_90);
    auto rotation = context_->GetDragManager().GetRotation(0);
    EXPECT_EQ(rotation, Rosen::Rotation::ROTATION_0);
}

/**
 * @tc.name: DisplayChangeEventListenerTest_HandleScreenRotation_004
 * @tc.desc: Test HandleScreenRotation with ROTATION_180 resets rotation to ROTATION_0
 * @tc.type: FUNC HandleScreenRotation
 * @tc.require:
 */
HWTEST_F(DisplayChangeEventListenerTest, DisplayChangeEventListenerTest_HandleScreenRotation_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(displayListener_, nullptr);
    context_->GetDragManager().SetRotation(0, Rosen::Rotation::ROTATION_90);
    displayListener_->HandleScreenRotation(0, Rosen::Rotation::ROTATION_180);
    auto rotation = context_->GetDragManager().GetRotation(0);
    EXPECT_EQ(rotation, Rosen::Rotation::ROTATION_0);
}

/**
 * @tc.name: DisplayChangeEventListenerTest_HandleScreenRotation_005
 * @tc.desc: Test HandleScreenRotation with ROTATION_270 resets rotation to ROTATION_0
 * @tc.type: FUNC HandleScreenRotation
 * @tc.require:
 */
HWTEST_F(DisplayChangeEventListenerTest, DisplayChangeEventListenerTest_HandleScreenRotation_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(displayListener_, nullptr);
    context_->GetDragManager().SetRotation(0, Rosen::Rotation::ROTATION_90);
    displayListener_->HandleScreenRotation(0, Rosen::Rotation::ROTATION_270);
    auto rotation = context_->GetDragManager().GetRotation(0);
    EXPECT_EQ(rotation, Rosen::Rotation::ROTATION_0);
}

/**
 * @tc.name: DisplayChangeEventListenerTest_HandleScreenRotation_006
 * @tc.desc: Test HandleScreenRotation with lastRotation same as preset rotation
 * @tc.type: FUNC HandleScreenRotation
 * @tc.require:
 */
HWTEST_F(DisplayChangeEventListenerTest, DisplayChangeEventListenerTest_HandleScreenRotation_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(displayListener_, nullptr);
    context_->GetDragManager().SetRotation(0, Rosen::Rotation::ROTATION_180);
    displayListener_->HandleScreenRotation(0, Rosen::Rotation::ROTATION_180);
    auto rotation = context_->GetDragManager().GetRotation(0);
    EXPECT_EQ(rotation, Rosen::Rotation::ROTATION_0);
}

/**
 * @tc.name: DisplayChangeEventListenerTest_ProcessDisplayEvent_002
 * @tc.desc: Test ProcessDisplayEvent verifies new call order: get currentRotation before IsRotateDragScreen
 * @tc.type: FUNC ProcessDisplayEvent
 * @tc.require:
 */
HWTEST_F(DisplayChangeEventListenerTest, DisplayChangeEventListenerTest_ProcessDisplayEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(displayListener_, nullptr);
    displayListener_->RotateDragWindow(0, Rosen::Rotation::ROTATION_90);
    auto displayInfo = displayListener_->GetDisplayInfo(0);
    ASSERT_NE(displayInfo, nullptr);
    displayListener_->ProcessDisplayEvent(0);
    auto rotation = context_->GetDragManager().GetRotation(0);
    EXPECT_EQ(rotation, Rosen::Rotation::ROTATION_0);
}

/**
 * @tc.name: DisplayChangeEventListenerTest_IsRotateDragScreen_001
 * @tc.desc: Test IsRotateDragScreen executes without crash on current device
 * @tc.type: FUNC IsRotateDragScreen
 * @tc.require:
 */
HWTEST_F(DisplayChangeEventListenerTest, DisplayChangeEventListenerTest_IsRotateDragScreen_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(displayListener_, nullptr);
    displayListener_->IsRotateDragScreen();
}

/**
 * @tc.name: DisplayChangeEventListenerTest_GetAllScreenAngles_001
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC GetAllScreenAngles
 * @tc.require:
 */
HWTEST_F(DisplayChangeEventListenerTest, DisplayChangeEventListenerTest_GetAllScreenAngles_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(displayListener_, nullptr);
    displayListener_->GetAllScreenAngles();
    auto displayInfo = displayListener_->GetDisplayInfo(-1);
    EXPECT_NE(displayInfo, nullptr);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
