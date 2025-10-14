/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include "input_adapter_test.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

#undef LOG_TAG
#define LOG_TAG "InputAdapterTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
using namespace OHOS::Security::AccessToken;
namespace {
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
std::mutex g_lockSetToken;
uint64_t g_shellTokenId = 0;
static constexpr int32_t DEFAULT_API_VERSION = 12;
static MockHapToken* g_mock = nullptr;
const std::string INPUT = { "ohos.permission.INPUT_MONITORING" };
const std::string INJECT = { "ohos.permission.INJECT_INPUT_EVENT" };
const std::string INTERCEPT = { "ohos.permission.INTERCEPT_INPUT_EVENT" };
const std::string FILTER = { "ohos.permission.FILTER_INPUT_EVENT" };
const std::string MANAGE = { "ohos.permission.MANAGE_MOUSE_CURSOR" };
} // namespace

void SetTestEvironment(uint64_t shellTokenId)
{
    std::lock_guard<std::mutex> lock(g_lockSetToken);
    g_shellTokenId = shellTokenId;
}

void ResetTestEvironment()
{
    std::lock_guard<std::mutex> lock(g_lockSetToken);
    g_shellTokenId = 0;
}

uint64_t GetShellTokenId()
{
    std::lock_guard<std::mutex> lock(g_lockSetToken);
    return g_shellTokenId;
}

AccessTokenID GetNativeTokenIdFromProcess(const std::string &process)
{
    uint64_t selfTokenId = GetSelfTokenID();
    EXPECT_EQ(0, SetSelfTokenID(GetShellTokenId())); // set shell token

    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.processName = process;
    AccessTokenKit::DumpTokenInfo(info, dumpInfo);
    size_t pos = dumpInfo.find("\"tokenID\": ");
    if (pos == std::string::npos) {
        FI_HILOGE("tokenid not find");
        return 0;
    }
    pos += std::string("\"tokenID\": ").length();
    std::string numStr;
    while (pos < dumpInfo.length() && std::isdigit(dumpInfo[pos])) {
        numStr += dumpInfo[pos];
        ++pos;
    }
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId));

    std::istringstream iss(numStr);
    AccessTokenID tokenID;
    iss >> tokenID;
    return tokenID;
}

int32_t AllocTestHapToken(const HapInfoParams& hapInfo, HapPolicyParams& hapPolicy,  AccessTokenIDEx& tokenIdEx)
{
    uint64_t selfTokenId = GetSelfTokenID();
    for (auto& permissionStateFull : hapPolicy.permStateList) {
        PermissionDef permDefResult;
        if (AccessTokenKit::GetDefPermission(permissionStateFull.permissionName, permDefResult) != RET_SUCCESS) {
            continue;
        }
        if (permDefResult.availableLevel > hapPolicy.apl) {
            hapPolicy.aclRequestedList.emplace_back(permissionStateFull.permissionName);
        }
    }
    if (GetNativeTokenIdFromProcess("foundation") == selfTokenId) {
        return AccessTokenKit::InitHapToken(hapInfo, hapPolicy, tokenIdEx);
    }
    // set sh token for self
    MockNativeToken mock("foundation");
    int32_t ret = AccessTokenKit::InitHapToken(hapInfo, hapPolicy, tokenIdEx);

    // restore
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId));
    return ret;
}

int32_t DeleteTestHapToken(AccessTokenID tokenID)
{
    uint64_t selfTokenId = GetSelfTokenID();
    if (GetNativeTokenIdFromProcess("foundation") == selfTokenId) {
        return AccessTokenKit::DeleteToken(tokenID);
    }
    MockNativeToken mock("foundation");
    int32_t ret = AccessTokenKit::DeleteToken(tokenID);
    SetSelfTokenID(selfTokenId);
    return ret;
}

MockNativeToken::MockNativeToken(const std::string& process)
{
    selfToken_ = GetSelfTokenID();
    uint32_t tokenId = GetNativeTokenIdFromProcess(process);
    FI_HILOGI("selfToken_:%{public}" PRId64 ", tokenId:%{public}u", selfToken_, tokenId);
    SetSelfTokenID(tokenId);
}

MockNativeToken::~MockNativeToken()
{
    SetSelfTokenID(selfToken_);
}

MockHapToken::MockHapToken(
    const std::string& bundle, const std::vector<std::string>& reqPerm, bool isSystemApp)
{
    selfToken_ = GetSelfTokenID();
    HapInfoParams infoParams = {
        .userID = 0,
        .bundleName = bundle,
        .instIndex = 0,
        .appIDDesc = "AccessTokenTestAppID",
        .apiVersion = DEFAULT_API_VERSION,
        .isSystemApp = isSystemApp,
        .appDistributionType = "",
    };

    HapPolicyParams policyParams = {
        .apl = APL_NORMAL,
        .domain = "accesstoken_test_domain",
    };
    for (size_t i = 0; i < reqPerm.size(); ++i) {
        PermissionDef permDefResult;
        if (AccessTokenKit::GetDefPermission(reqPerm[i], permDefResult) != RET_SUCCESS) {
            continue;
        }
        PermissionStateFull permState = {
            .permissionName = reqPerm[i],
            .isGeneral = true,
            .resDeviceID = {"local3"},
            .grantStatus = {PermissionState::PERMISSION_GRANTED},
            .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG}
        };
        policyParams.permStateList.emplace_back(permState);
        if (permDefResult.availableLevel > policyParams.apl) {
            policyParams.aclRequestedList.emplace_back(reqPerm[i]);
        }
    }

    AccessTokenIDEx tokenIdEx = {0};
    EXPECT_EQ(RET_SUCCESS, AllocTestHapToken(infoParams, policyParams, tokenIdEx));
    mockToken_= tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_NE(mockToken_, INVALID_TOKENID);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));
}

MockHapToken::~MockHapToken()
{
    if (mockToken_ != INVALID_TOKENID) {
        EXPECT_EQ(0, DeleteTestHapToken(mockToken_));
    }
    EXPECT_EQ(0, SetSelfTokenID(selfToken_));
}

void InputAdapterTest::SetUpTestCase()
{
    SetTestEvironment(g_shellTokenId);
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back(INPUT);
    reqPerm.emplace_back(INJECT);
    reqPerm.emplace_back(INTERCEPT);
    reqPerm.emplace_back(FILTER);
    reqPerm.emplace_back(MANAGE);
    g_mock = new (std::nothrow) MockHapToken("InputAdapterTest", reqPerm, true);
    FI_HILOGI("SetUpTestCase ok.");  
}

void InputAdapterTest::TearDownTestCase()
{
    if (g_mock != nullptr) {
        delete g_mock;
        g_mock = nullptr;
    }
    std::lock_guard<std::mutex> lock(g_lockSetToken);
    g_shellTokenId = 0;
    SetSelfTokenID(g_shellTokenId);
}

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
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    auto callback = [] (std::shared_ptr<OHOS::MMI::PointerEvent>) {
        FI_HILOGI("OnEvent");
    };
    int32_t monitorId = inputAdapter->AddMonitor(callback);
    ASSERT_NO_FATAL_FAILURE(inputAdapter->RemoveMonitor(monitorId));
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
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    auto callback = [] (std::shared_ptr<OHOS::MMI::KeyEvent>) {
        FI_HILOGI("OnEvent");
    };
    int32_t monitorId = inputAdapter->AddMonitor(callback);
    ASSERT_NO_FATAL_FAILURE(inputAdapter->RemoveMonitor(monitorId));
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
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    auto callback = [] (std::shared_ptr<OHOS::MMI::KeyEvent>) {
        FI_HILOGI("OnEvent");
    };
    int32_t interceptorId = inputAdapter->AddInterceptor(callback);
    ASSERT_TRUE(interceptorId > 0);
    inputAdapter->RemoveInterceptor(interceptorId);

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
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    auto callback = [] (std::shared_ptr<OHOS::MMI::PointerEvent>) {
        FI_HILOGI("OnEvent");
    };
    int32_t interceptorId = inputAdapter->AddInterceptor(callback);
    ASSERT_TRUE(interceptorId > 0);
    inputAdapter->RemoveInterceptor(interceptorId);
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
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    auto filterCallback = [] (std::shared_ptr<OHOS::MMI::PointerEvent>) -> bool {
        FI_HILOGI("OnEvent");
        return true;
    };
    int32_t filterId = inputAdapter->AddFilter(filterCallback);
    ASSERT_FALSE(filterId > 0);
    inputAdapter->RemoveFilter(filterId);
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
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    int32_t filterId = inputAdapter->SetPointerVisibility(true);
    ASSERT_FALSE(filterId > 0);
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
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    int32_t ret= inputAdapter->SetPointerLocation(0, 0);
    EXPECT_EQ(RET_OK, ret);
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
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    int32_t ret = inputAdapter->EnableInputDevice(true);
    ASSERT_EQ(ret, RET_OK);
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
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    ASSERT_NO_FATAL_FAILURE(inputAdapter->SimulateInputEvent(MMI::KeyEvent::Create()));
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
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    ASSERT_NO_FATAL_FAILURE(inputAdapter->SimulateInputEvent(MMI::PointerEvent::Create()));
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
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    auto callback = [] (std::shared_ptr<OHOS::MMI::PointerEvent>) {};
    int32_t monitorId = inputAdapter->AddMonitor(callback);
    ASSERT_NO_FATAL_FAILURE(inputAdapter->RemoveMonitor(monitorId));
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
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    auto callback = [] (std::shared_ptr<OHOS::MMI::KeyEvent>) {};
    int32_t monitorId = inputAdapter->AddMonitor(callback);
    ASSERT_NO_FATAL_FAILURE(inputAdapter->RemoveMonitor(monitorId));
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
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    int32_t interceptorId = inputAdapter->AddInterceptor(nullptr, nullptr);
    ASSERT_EQ(interceptorId, RET_ERR);
    inputAdapter->RemoveInterceptor(interceptorId);
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
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    auto filterCallback = [] (std::shared_ptr<OHOS::MMI::PointerEvent>) -> bool {
        FI_HILOGI("OnEvent");
        return false;
    };
    int32_t filterId = inputAdapter->AddFilter(filterCallback);
    ASSERT_TRUE(filterId > 0);
    inputAdapter->RemoveFilter(filterId);
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
    InterceptorConsumer interceptorConsumer1 {
        [](std::shared_ptr<MMI::PointerEvent> cb) -> void {},
        [](std::shared_ptr<MMI::KeyEvent> cb) -> void {}
    };
    std::shared_ptr<MMI::PointerEvent> pointerEvent =  MMI::PointerEvent::Create();
    std::shared_ptr<MMI::KeyEvent> keyEvent = MMI::KeyEvent::Create();
    ASSERT_NO_FATAL_FAILURE(interceptorConsumer1.OnInputEvent(pointerEvent));
    ASSERT_NO_FATAL_FAILURE(interceptorConsumer1.OnInputEvent(keyEvent));
}

/**
 * @tc.name: TestRegisterDevListener1
 * @tc.desc: Test RegisterDevListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputAdapterTest, RegisterDevListener1, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    int32_t ret = inputAdapter->RegisterDevListener(nullptr, nullptr);
    ASSERT_EQ(ret, RET_ERR);
    inputAdapter->UnregisterDevListener();
}
 
/**
 * @tc.name: TestRegisterDevListener2
 * @tc.desc: Test RegisterDevListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputAdapterTest, RegisterDevListener2, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    auto devAddedCallback = [this](int32_t deviceId, const std::string &type) {
        FI_HILOGI("Device added");
    };
    auto devRemovedCallback = [this](int32_t deviceId, const std::string &type) {
        FI_HILOGI("Device removed");
    };
    int32_t ret = inputAdapter->RegisterDevListener(devAddedCallback, devRemovedCallback);
    ASSERT_EQ(ret, RET_OK);
    inputAdapter->UnregisterDevListener();
}

} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
