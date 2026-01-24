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
 * @tc.name: DisplayChangeEventListenerTest_OnChange_001
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC OnChange
 * @tc.require:
 */
HWTEST_F(DisplayChangeEventListenerTest, DisplayChangeEventListenerTest_OnChange_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(displayListener_, nullptr);
    displayListener_->RotateDragWindow(0, Rosen::Rotation::ROTATION_90);
    auto displayInfo = displayListener_->GetDisplayInfo(0);
    displayListener_->OnChange(0);
    EXPECT_NE(displayInfo, nullptr);
}

/**
 * @tc.name: DisplayChangeEventListenerTest_OnChange_002
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC OnChange
 * @tc.require:
 */
HWTEST_F(DisplayChangeEventListenerTest, DisplayChangeEventListenerTest_OnChange_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(displayListener_, nullptr);
    auto displayInfo = displayListener_->GetDisplayInfo(-1);
    displayListener_->OnChange(-1);
    EXPECT_NE(displayInfo, nullptr);
}

/**
 * @tc.name: DisplayChangeEventListenerTest_HandleScreenRotation_001
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC HandleScreenRotation
 * @tc.require:
 */
HWTEST_F(DisplayChangeEventListenerTest, DisplayChangeEventListenerTest_HandleScreenRotation_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(displayListener_, nullptr);
    auto displayInfo = displayListener_->GetDisplayInfo(-1);
    displayListener_->HandleScreenRotation(0, Rosen::Rotation::ROTATION_0);
    EXPECT_NE(displayInfo, nullptr);
}

/**
 * @tc.name: DisplayChangeEventListenerTest_HandleScreenRotation_002
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC HandleScreenRotation
 * @tc.require:
 */
HWTEST_F(DisplayChangeEventListenerTest, DisplayChangeEventListenerTest_HandleScreenRotation_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(displayListener_, nullptr);
    DisplayChangeEventListener listener(nullptr);
    auto displayInfo = displayListener_->GetDisplayInfo(-1);
    listener.HandleScreenRotation(0, Rosen::Rotation::ROTATION_90);
    EXPECT_NE(displayInfo, nullptr);
}

/**
 * @tc.name: DisplayChangeEventListenerTest_HandleScreenRotation_003
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC HandleScreenRotation
 * @tc.require:
 */
HWTEST_F(DisplayChangeEventListenerTest, DisplayChangeEventListenerTest_HandleScreenRotation_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(displayListener_, nullptr);
    displayListener_->HandleScreenRotation(0, Rosen::Rotation::ROTATION_90);
    auto rotation = context_->GetDragManager().GetRotation(0);
    EXPECT_EQ(rotation, Rosen::Rotation::ROTATION_0);
}

/**
 * @tc.name: DisplayChangeEventListenerTest_HandleScreenRotation_004
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC HandleScreenRotation
 * @tc.require:
 */
HWTEST_F(DisplayChangeEventListenerTest, DisplayChangeEventListenerTest_HandleScreenRotation_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(displayListener_, nullptr);
    displayListener_->HandleScreenRotation(0, Rosen::Rotation::ROTATION_180);
    auto rotation = context_->GetDragManager().GetRotation(0);
    EXPECT_EQ(rotation, Rosen::Rotation::ROTATION_0);
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
