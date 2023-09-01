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

#include <gtest/gtest.h>

#include "coordination_sm.h"
#include "coordination_sm_test.h"
#include "coordination_util.h"
#include "fi_log.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
constexpr ::OHOS::HiviewDFX::HiLogLabel LABEL { LOG_CORE, MSDP_DOMAIN_ID, "CoordinationSMTest" };
} // namespace

void CoordinationSMTest::SetUpTestCase() {}

void CoordinationSMTest::TearDownTestCase() {}

void CoordinationSMTest::SetUp() {
    AddPermission();
}

void CoordinationSMTest::TearDown() {}

/**
 * @tc.name: CoordinationSMTest
 * @tc.desc: test IsNeedFilterOut state == CoordinationState::STATE_OUT
 * @tc.type: FUNC
 */
HWTEST_F(CoordinationSMTest, CoordinationSMTest001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string localNetworkId = COORDINATION::GetLocalNetworkId();
    std::shared_ptr<MMI::KeyEvent> keyEvent = MMI::KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_BACK);
    keyEvent->SetActionTime(1);
    keyEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_DOWN);
    OHOS::MMI::KeyEvent::KeyItem item;
    item.SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_BACK);
    item.SetDownTime(1);
    item.SetPressed(true);
    keyEvent->AddKeyItem(item);
    bool ret = COOR_SM->IsNeedFilterOut(localNetworkId, keyEvent);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.name: CoordinationSMTest
 * @tc.desc: test GetCoordinationState when localNetworkId is empty
 * @tc.type: FUNC
 */
HWTEST_F(CoordinationSMTest, CoordinationSMTest002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string localNetworkId = "";
    int32_t ret = COOR_SM->GetCoordinationState(localNetworkId);
    ASSERT_TRUE(ret == static_cast<int32_t>(CoordinationMessage::PARAMETER_ERROR));
}

/**
 * @tc.name: CoordinationSMTest
 * @tc.desc: test GetCoordinationState when localNetworkId is right
 * @tc.type: FUNC
 */
HWTEST_F(CoordinationSMTest, CoordinationSMTest003, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string localNetworkId = COORDINATION::GetLocalNetworkId();
    int32_t ret = COOR_SM->GetCoordinationState(localNetworkId);
    ASSERT_TRUE(ret == 0);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS