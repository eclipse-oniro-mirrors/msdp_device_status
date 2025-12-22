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
#include "on_screen_manager.h"
#include "on_screen_data.h"
#include "iremote_on_screen_callback.h"

using namespace testing::ext;
#undef LOG_TAG
#define LOG_TAG "OnScreenManagerTest"
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
class OnScreenManagerTest : public testing::Test {
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
 * @tc.name: RegisterAwarenessCallback
 * @tc.desc: test for RegisterAwarenessCallback
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenManagerTest, RegisterAwarenessCallback, TestSize.Level1)
{
    AwarenessCap cap;
    sptr<IRemoteOnScreenCallbackTest> callback = new (std::nothrow) IRemoteOnScreenCallbackTest();
    EXPECT_NE(callback, nullptr);

    AwarenessOptions option;
    auto result = OnScreenManager::GetInstance().RegisterAwarenessCallback(cap, callback, option);
    EXPECT_NE(result, 0);
}

/**
 * @tc.name: UnregisterAwarenessCallback
 * @tc.desc: Test for UnregisterAwarenessCallback
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenManagerTest, UnregisterAwarenessCallback, TestSize.Level1)
{
    AwarenessCap cap;
    sptr<IRemoteOnScreenCallbackTest> callback = new (std::nothrow) IRemoteOnScreenCallbackTest();
    EXPECT_NE(callback, nullptr);

    auto result = OnScreenManager::GetInstance().UnregisterAwarenessCallback(cap, callback);
    EXPECT_NE(result, 0);
}

/**
 * @tc.name: Trigger
 * @tc.desc: Test for Trigger
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenManagerTest, Trigger, TestSize.Level1)
{
    AwarenessCap cap;
    AwarenessOptions option;
    OnscreenAwarenessInfo info;
    auto result = OnScreenManager::GetInstance().Trigger(cap, option, info);
    EXPECT_NE(result, 0);
}
}  // namespace OnScreen
}  // namespace DeviceStatus
}  // namespace Msdp
}  // namespace OHOS