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
 
#include "intention_manager.h"
#include "iremote_on_screen_callback.h"
#include "on_screen_data.h"
using namespace testing::ext;
#undef LOG_TAG
#define LOG_TAG "IntentionManagerTest"
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
 
class IntentionManagerTest : public testing::Test {
public:
    void SetUp(){};
    void TearDown(){};
    static void SetUpTestCase(){};
    static void TearDownTestCase(){};
};
 
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
 * @tc.name: IntentionManagerTest_RegisterAwarenessCallback
 * @tc.desc: Check RegisterAwarenessCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionManagerTest, IntentionManagerTest_RegisterAwarenessCallback, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    OnScreen::AwarenessCap cap;
    sptr<IRemoteOnScreenCallbackTest> callback = new (std::nothrow) IRemoteOnScreenCallbackTest();
    OnScreen::AwarenessOptions option;
    int32_t ret = OHOS::Singleton<IntentionManager>::GetInstance().RegisterAwarenessCallback(cap, callback, option);
    EXPECT_NE(ret, 0);
}
 
/**
 * @tc.name: IntentionManagerTest_UnregisterAwarenessCallback
 * @tc.desc: Check UnregisterAwarenessCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionManagerTest, IntentionManagerTest_UnregisterAwarenessCallback, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    OnScreen::AwarenessCap cap;
    sptr<IRemoteOnScreenCallbackTest> callback = new (std::nothrow) IRemoteOnScreenCallbackTest();
    int32_t ret = OHOS::Singleton<IntentionManager>::GetInstance().UnregisterAwarenessCallback(cap, callback);
    EXPECT_NE(ret, 0);
}
 
/**
 * @tc.name: IntentionManagerTest_UnRegisterAwarenessCallback01
 * @tc.desc: Check UnRegisterAwarenessCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionManagerTest, IntentionManagerTest_UnRegisterAwarenessCallback01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    OnScreen::AwarenessCap cap;
    OnScreen::AwarenessOptions option;
    OnScreen::OnscreenAwarenessInfo info;
    int32_t ret = OHOS::Singleton<IntentionManager>::GetInstance().Trigger(cap, option, info);
    EXPECT_NE(ret, 0);
}
}  // namespace DeviceStatus
}  // namespace Msdp
}  // namespace OHOS