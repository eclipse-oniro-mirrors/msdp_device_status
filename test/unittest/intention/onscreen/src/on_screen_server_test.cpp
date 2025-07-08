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

#include <gtest/gtest.h>

#include "devicestatus_define.h"
#include "fi_log.h"
#include "on_screen_data.h"
#include "on_screen_server.h"
#include "ipc_skeleton.h"

#undef LOG_TAG
#define LOG_TAG "OnScreenServerTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
using namespace testing::ext;
CallingContext context_ {
    .intention = Intention::UNKNOWN_INTENTION,
    .tokenId = IPCSkeleton::GetCallingTokenID(),
    .uid = IPCSkeleton::GetCallingUid(),
    .pid = IPCSkeleton::GetCallingPid(),
};
OnScreenServer onScreen_;
constexpr int32_t RET_NO_SUPPORT = 801;
class OnScreenServerTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: GetPageContent001
 * @tc.desc: Test func named GetPageContent
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, GetPageContent001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    ContentOption option;
    PageContent content;
    int32_t ret = onScreen_.GetPageContent(context_, option, content);
    EXPECT_TRUE(ret == RET_NO_SUPPORT || ret == RET_OK);
}

/**
 * @tc.name: SendControlEvent001
 * @tc.desc: Test func named  SendControlEvent
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, SendControlEvent001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    ControlEvent event;
    event.eventType = EventType::SCROLL_TO_HOOK;
    int32_t ret = onScreen_.SendControlEvent(context_, event);
    EXPECT_TRUE(ret == RET_NO_SUPPORT || ret == RET_OK);
}
} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS