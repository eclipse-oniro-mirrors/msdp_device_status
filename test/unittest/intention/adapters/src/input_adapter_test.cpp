/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <memory>
#include <utility>
#include <vector>

#include <unistd.h>

#include "accesstoken_kit.h"
#include <gtest/gtest.h>
#include "input_device.h"
#include "pointer_event.h"
#include "securec.h"

#include "devicestatus_define.h"
#include "devicestatus_errors.h"
#include "input_adapter.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

#undef LOG_TAG
#define LOG_TAG "InputAdapterTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
const std::string SYSTEM_CORE { "system_core" };
uint64_t g_tokenID { 0 };
} // namespace

class InputAdapterTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase();
    static void SetPermission();
    static void RemovePermission();
};

void InputAdapterTest::SetPermission()
{
    CALL_DEBUG_ENTER;
    const char** perms = new const char *[5];
    perms[0] = "ohos.permission.INPUT_MONITORING";
    perms[1] = "ohos.permission.INJECT_INPUT_EVENT";
    perms[2] = "ohos.permission.INTERCEPT_INPUT_EVENT";
    perms[3] = "ohos.permission.FILTER_INPUT_EVENT";
    perms[4] = "ohos.permission.MANAGE_MOUSE_CURSOR";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 5,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "InputAdapterTest",
        .aplStr = SYSTEM_CORE.c_str(),
    };
    g_tokenID = GetAccessTokenId(&infoInstance);
    EXPECT_EQ(0, SetSelfTokenID(g_tokenID));
    OHOS::Security::AccessToken::AccessTokenKit::AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
}

void InputAdapterTest::RemovePermission()
{
    CALL_DEBUG_ENTER;
    int32_t ret = OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenID);
    if (ret != RET_OK) {
        FI_HILOGE("Failed to remove permission");
        return;
    }
}

void InputAdapterTest::SetUpTestCase() {}

void InputAdapterTest::SetUp() {}

void InputAdapterTest::TearDown()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

/**
 * @tc.name: TestPointerAddMonitor
 * @tc.desc: Test AddMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputAdapterTest, TestPointerAddMonitor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission();
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    auto callback = [] (std::shared_ptr<OHOS::MMI::PointerEvent>) {
        FI_HILOGI("OnEvent");
    };
    int32_t monitorId = inputAdapter->AddMonitor(callback);
    ASSERT_NO_FATAL_FAILURE(inputAdapter->RemoveMonitor(monitorId));
    RemovePermission();
}

/**
 * @tc.name: TestPointerAddMonitor
 * @tc.desc: Test AddMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputAdapterTest, TestKeyAddMonitor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission();
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    auto callback = [] (std::shared_ptr<OHOS::MMI::KeyEvent>) {
        FI_HILOGI("OnEvent");
    };
    int32_t monitorId = inputAdapter->AddMonitor(callback);
    ASSERT_NO_FATAL_FAILURE(inputAdapter->RemoveMonitor(monitorId));
    RemovePermission();
}

/**
 * @tc.name: TestAddKeyEventInterceptor
 * @tc.desc: Test AddKeyEventInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputAdapterTest, AddKeyEventInterceptor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission();
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    auto callback = [] (std::shared_ptr<OHOS::MMI::KeyEvent>) {
        FI_HILOGI("OnEvent");
    };
    int32_t interceptorId = inputAdapter->AddInterceptor(callback);
    ASSERT_TRUE(interceptorId > 0);
    inputAdapter->RemoveInterceptor(interceptorId);
    RemovePermission();
}

/**
 * @tc.name: TestAddPointerEventInterceptor
 * @tc.desc: Test AddPointerEventInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputAdapterTest, AddPointerEventInterceptor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission();
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    auto callback = [] (std::shared_ptr<OHOS::MMI::PointerEvent>) {
        FI_HILOGI("OnEvent");
    };
    int32_t interceptorId = inputAdapter->AddInterceptor(callback);
    ASSERT_TRUE(interceptorId > 0);
    inputAdapter->RemoveInterceptor(interceptorId);
    RemovePermission();
}

/**
 * @tc.name: TestAddBothEventInterceptor
 * @tc.desc: Test AddBothEventInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputAdapterTest, AddBothEventInterceptor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission();
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    auto pointerCallback = [] (std::shared_ptr<OHOS::MMI::PointerEvent>) {
        FI_HILOGI("OnEvent");
    };
    auto keyCallback = [] (std::shared_ptr<OHOS::MMI::KeyEvent>) {
        FI_HILOGI("OnEvent");
    };
    int32_t interceptorId = inputAdapter->AddInterceptor(pointerCallback, keyCallback);
    ASSERT_TRUE(interceptorId > 0);
    inputAdapter->RemoveInterceptor(interceptorId);
    RemovePermission();
}

/**
 * @tc.name: TestAddFilter
 * @tc.desc: Test AddFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputAdapterTest, AddFilter, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission();
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    auto filterCallback = [] (std::shared_ptr<OHOS::MMI::PointerEvent>) -> bool {
        FI_HILOGI("OnEvent");
        return true;
    };
    int32_t filterId = inputAdapter->AddFilter(filterCallback);
    ASSERT_FALSE(filterId > 0);
    inputAdapter->RemoveFilter(filterId);
    RemovePermission();
}

/**
 * @tc.name: TestSetPointerVisibility
 * @tc.desc: Test SetPointerVisibility
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputAdapterTest, TestSetPointerVisibility, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission();
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    int32_t filterId = inputAdapter->SetPointerVisibility(true);
    ASSERT_FALSE(filterId > 0);
    RemovePermission();
}

/**
 * @tc.name: TestSetPointerLocation
 * @tc.desc: Test SetPointerLocation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputAdapterTest, TestSetPointerLocation, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission();
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    int32_t ret= inputAdapter->SetPointerLocation(0, 0);
    EXPECT_EQ(RET_OK, ret);
    RemovePermission();
}

/**
 * @tc.name: TestEnableInputDevice
 * @tc.desc: Test EnableInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputAdapterTest, TestEnableInputDevice, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission();
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    int32_t ret = inputAdapter->EnableInputDevice(true);
    ASSERT_EQ(ret, RET_OK);
    RemovePermission();
}

/**
 * @tc.name: TestSimulateKeyEvent
 * @tc.desc: Test SimulateKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputAdapterTest, TestSimulateKeyEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission();
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    ASSERT_NO_FATAL_FAILURE(inputAdapter->SimulateInputEvent(MMI::KeyEvent::Create()));
    RemovePermission();
}

/**
 * @tc.name: TestSimulatePointerEvent
 * @tc.desc: Test SimulatePointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputAdapterTest, TestSimulatePointerEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission();
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    ASSERT_NO_FATAL_FAILURE(inputAdapter->SimulateInputEvent(MMI::PointerEvent::Create()));
    RemovePermission();
}

/**
 * @tc.name: TestPointerAddMonitor1
 * @tc.desc: Test AddMonitor1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputAdapterTest, TestPointerAddMonitor1, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission();
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    auto callback = [] (std::shared_ptr<OHOS::MMI::PointerEvent>) {};
    int32_t monitorId = inputAdapter->AddMonitor(callback);
    ASSERT_NO_FATAL_FAILURE(inputAdapter->RemoveMonitor(monitorId));
    RemovePermission();
}

/**
 * @tc.name: TestPointerAddMonitor1
 * @tc.desc: Test AddMonitor1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputAdapterTest, TestKeyAddMonitor1, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission();
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    auto callback = [] (std::shared_ptr<OHOS::MMI::KeyEvent>) {};
    int32_t monitorId = inputAdapter->AddMonitor(callback);
    ASSERT_NO_FATAL_FAILURE(inputAdapter->RemoveMonitor(monitorId));
    RemovePermission();
}

/**
 * @tc.name: TestAddKeyEventInterceptor1
 * @tc.desc: Test AddKeyEventInterceptor1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputAdapterTest, AddKeyEventInterceptor1, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission();
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    int32_t interceptorId = inputAdapter->AddInterceptor(nullptr, nullptr);
    ASSERT_EQ(interceptorId, RET_ERR);
    inputAdapter->RemoveInterceptor(interceptorId);
    RemovePermission();
}

/**
 * @tc.name: TestAddFilter1
 * @tc.desc: Test AddFilter1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputAdapterTest, AddFilter1, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission();
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    auto filterCallback = [] (std::shared_ptr<OHOS::MMI::PointerEvent>) -> bool {
        FI_HILOGI("OnEvent");
        return false;
    };
    int32_t filterId = inputAdapter->AddFilter(filterCallback);
    ASSERT_TRUE(filterId > 0);
    inputAdapter->RemoveFilter(filterId);
    RemovePermission();
}

/**
 * @tc.name: TestOnInputEvent
 * @tc.desc: Test OnInputEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputAdapterTest, TesOnInputEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission();
    auto pointerCb = [](std::shared_ptr<MMI::PointerEvent> pointerEvent) {
        pointerEvent =  MMI::PointerEvent::Create();
        return ;
    };
    auto keyCb = [](std::shared_ptr<MMI::KeyEvent>keyEvent) {
        keyEvent = MMI::KeyEvent::Create();
        return ;
    };
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    std::shared_ptr<MMI::PointerEvent> pointerEvent =  MMI::PointerEvent::Create();
    std::shared_ptr<MMI::KeyEvent> keyEvent = MMI::KeyEvent::Create();
    InterceptorConsumer interceptorConsumer { pointerCb, keyCb };
    ASSERT_NO_FATAL_FAILURE(interceptorConsumer.OnInputEvent(pointerEvent));
    ASSERT_NO_FATAL_FAILURE(interceptorConsumer.OnInputEvent(keyEvent));
    RemovePermission();
}

/**
 * @tc.name: TestOnInputEvent1
 * @tc.desc: Test OnInputEvent1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputAdapterTest, TestOnInputEvent1, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission();
    InterceptorConsumer interceptorConsumer1 {
        [](std::shared_ptr<MMI::PointerEvent> cb) -> void {},
        [](std::shared_ptr<MMI::KeyEvent> cb) -> void {}
    };
    std::shared_ptr<MMI::PointerEvent> pointerEvent =  MMI::PointerEvent::Create();
    std::shared_ptr<MMI::KeyEvent> keyEvent = MMI::KeyEvent::Create();
    ASSERT_NO_FATAL_FAILURE(interceptorConsumer1.OnInputEvent(pointerEvent));
    ASSERT_NO_FATAL_FAILURE(interceptorConsumer1.OnInputEvent(keyEvent));
    RemovePermission();
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
