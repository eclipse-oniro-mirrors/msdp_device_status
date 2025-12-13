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
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
