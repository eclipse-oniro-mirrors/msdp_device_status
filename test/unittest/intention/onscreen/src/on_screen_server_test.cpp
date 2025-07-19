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

#include "accesstoken_kit.h"
#include "devicestatus_define.h"
#include "fi_log.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "on_screen_data.h"
#include "on_screen_server.h"
#include "token_setproc.h"

#undef LOG_TAG
#define LOG_TAG "OnScreenServerTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
using namespace testing::ext;
using namespace Security::AccessToken;
OnScreenServer onScreen_;
uint64_t tokenId_ = 0;
const char *PERMISSION_GET_PAGE_CONTENT = "ohos.permission.GET_SCREEN_CONTENT";
const char *PERMISSION_SEND_CONTROL_EVENT = "ohos.permission.SIMULATE_USER_INPUT";
class OnScreenServerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() {};
    void TearDown() {};
};

void OnScreenServerTest::SetUpTestCase()
{
    const char **perms = new (std::nothrow) const char *[2];
    if (perms == nullptr) {
        return;
    }
    perms[0] = PERMISSION_GET_PAGE_CONTENT;
    perms[1] = PERMISSION_SEND_CONTROL_EVENT;
    TokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "OnScreenServerTest",
        .aplStr = "system_core",
    };
    tokenId_ = GetAccessTokenId(&infoInstance);
}

void OnScreenServerTest::TearDownTestCase()
{
    int32_t ret = AccessTokenKit::DeleteToken(tokenId_);
    if (ret != RET_OK) {
        FI_HILOGE("failed to remove permission");
        return;
    }
}

/**
 * @tc.name: GetPageContent001
 * @tc.desc: Test func named GetPageContent
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, GetPageContent001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context;
    context.tokenId = tokenId_;
    ContentOption option;
    PageContent content;
    int32_t ret = onScreen_.GetPageContent(context, option, content);
    EXPECT_TRUE(ret >= RET_ERR);
}

/**
 * @tc.name: SendControlEvent001
 * @tc.desc: Test func named  SendControlEvent
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, SendControlEvent001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context;
    context.tokenId = tokenId_;
    ControlEvent event;
    event.eventType = EventType::SCROLL_TO_HOOK;
    int32_t ret = onScreen_.SendControlEvent(context, event);
    EXPECT_TRUE(ret >= RET_ERR);
}

/**
 * @tc.name: IsSystemCalling001
 * @tc.desc: Test func named IsSystemCalling
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, IsSystemCalling001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = Intention::UNKNOWN_INTENTION,
        .fullTokenId = (static_cast<uint64_t>(1) << 32);
        .tokenId = 0,
        .uid = 0,
        .pid = 0,
    };
    EXPECT_EQ(onScreen_.IsSystemCalling(context), true);
    context.fullTokenId = 0;
    EXPECT_EQ(onScreen_.IsSystemCalling(context), false);
}
} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS