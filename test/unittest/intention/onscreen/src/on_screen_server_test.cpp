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
#include "on_screen_server_test.h"
#include "token_setproc.h"

#undef LOG_TAG
#define LOG_TAG "OnScreenServerTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
using namespace testing::ext;
using namespace Security::AccessToken;
namespace {
OnScreenServer onScreen_;
uint64_t tokenId_ = 0;
const char *PERMISSION_GET_PAGE_CONTENT = "ohos.permission.GET_SCREEN_CONTENT";
const char *PERMISSION_SEND_CONTROL_EVENT = "ohos.permission.SIMULATE_USER_INPUT";
std::mutex g_lockSetToken;
uint64_t g_shellTokenId = 0;
static constexpr int32_t DEFAULT_API_VERSION = 12;
static MockHapToken* g_mock = nullptr;
constexpr int32_t RET_NO_SYSTEM_CALLING = 202;
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
    EXPECT_EQ(0, SetSelfTokenID(GetShellTokenId())); // Set shell token

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

uint64_t NativeTokenGet()
{
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 0,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = nullptr,
        .acls = nullptr,
        .aplStr = "system_basic",
    };

    infoInstance.processName = " DragServerTest";
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
    return tokenId;
}

void OnScreenServerTest::SetUp()
{}

void OnScreenServerTest::TearDown()
{
    onScreen_.handle_.pAlgorithm = nullptr;
}

void OnScreenServerTest::SetUpTestCase()
{
    g_shellTokenId = GetSelfTokenID();
    SetTestEvironment(g_shellTokenId);
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back(PERMISSION_GET_PAGE_CONTENT);
    reqPerm.emplace_back(PERMISSION_SEND_CONTROL_EVENT);
    g_mock = new (std::nothrow) MockHapToken("OnScreenServerTest", reqPerm, true);
    CHKPV(g_mock);
    FI_HILOGI("SetUpTestCase ok.");
}

void OnScreenServerTest::TearDownTestCase()
{
    if (g_mock != nullptr) {
        delete g_mock;
        g_mock = nullptr;
    }
    std::lock_guard<std::mutex> lock(g_lockSetToken);
    g_shellTokenId = 0;
    SetSelfTokenID(g_shellTokenId);
}

void OnScreenServerTest::OnScreenServerTestCallback::OnScreenChange(const std::string& changeInfo)
{
    FI_HILOGI("OnScreenChange");
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
 * @tc.name: GetPageContent002
 * @tc.desc: Test func named GetPageContent
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, GetPageContent002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    ContentOption option;
    PageContent content;
    bool ret = onScreen_.IsSystemCalling(context);
    ASSERT_TRUE(ret);
    ret = onScreen_.CheckPermission(context, PERMISSION_GET_PAGE_CONTENT);
    ASSERT_TRUE(ret);
    int32_t ret1 = onScreen_.GetPageContent(context, option, content);
    EXPECT_TRUE(ret1 >= RET_ERR);
    context.fullTokenId = tokenId_;
    ret = onScreen_.IsSystemCalling(context);
    ASSERT_FALSE(ret);
    ret1 = onScreen_.GetPageContent(context, option, content);
    EXPECT_TRUE(ret1 == RET_NO_SYSTEM_CALLING);
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
 * @tc.name: SendControlEvent002
 * @tc.desc: Test func named  SendControlEvent
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, SendControlEvent002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    bool ret = onScreen_.IsSystemCalling(context);
    ASSERT_TRUE(ret);
    ret = onScreen_.CheckPermission(context, PERMISSION_SEND_CONTROL_EVENT);
    ASSERT_TRUE(ret);
    ControlEvent event;
    event.eventType = EventType::SCROLL_TO_HOOK;
    int32_t ret1 = onScreen_.SendControlEvent(context, event);
    EXPECT_TRUE(ret1 >= RET_ERR);
    context.fullTokenId = tokenId_,
    ret = onScreen_.IsSystemCalling(context);
    ASSERT_FALSE(ret);
    ret1 = onScreen_.SendControlEvent(context, event);
    EXPECT_TRUE(ret1 == RET_NO_SYSTEM_CALLING);
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
        .fullTokenId = (static_cast<uint64_t>(1) << 32),
        .tokenId = 0,
        .uid = 0,
        .pid = 0,
    };
    EXPECT_EQ(onScreen_.IsSystemCalling(context), true);
    context.fullTokenId = 0;
    EXPECT_EQ(onScreen_.IsSystemCalling(context), false);
}

/**
 * @tc.name: IsSystemCalling002
 * @tc.desc: Test func named IsSystemCalling
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, IsSystemCalling002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context {
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    EXPECT_EQ(onScreen_.IsSystemCalling(context), true);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: RegisterScreenEventCallback001
 * @tc.desc: Test func named RegisterScreenEventCallback
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, RegisterScreenEventCallback001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context {
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    EXPECT_EQ(onScreen_.IsSystemCalling(context), true);
    int32_t windowId = 1;
    std::string event = "test";
    sptr<IRemoteOnScreenCallback> callback = new (std::nothrow) OnScreenServerTestCallback();
    ASSERT_NE(callback, nullptr);
    int32_t ret = onScreen_.RegisterScreenEventCallback(context, windowId, event, callback);
    EXPECT_EQ(ret, RET_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: RegisterScreenEventCallback002
 * @tc.desc: Test func named RegisterScreenEventCallback
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, RegisterScreenEventCallback002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context {
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    EXPECT_EQ(onScreen_.IsSystemCalling(context), true);
    int32_t windowId = 1;
    std::string event = "test";
    sptr<IRemoteOnScreenCallback> callback { nullptr };
    int32_t ret = onScreen_.RegisterScreenEventCallback(context, windowId, event, callback);
    EXPECT_EQ(ret, RET_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: UnregisterScreenEventCallback001
 * @tc.desc: Test func named UnregisterScreenEventCallback
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, UnregisterScreenEventCallback001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context {
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    EXPECT_EQ(onScreen_.IsSystemCalling(context), true);
    int32_t windowId = 1;
    std::string event = "test";
    sptr<IRemoteOnScreenCallback> callback = new (std::nothrow) OnScreenServerTestCallback();
    ASSERT_NE(callback, nullptr);
    int32_t ret = onScreen_.UnregisterScreenEventCallback(context, windowId, event, callback);
    EXPECT_NE(ret, RET_OK);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: UnregisterScreenEventCallback002
 * @tc.desc: Test func named UnregisterScreenEventCallback
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, UnregisterScreenEventCallback002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context {
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    EXPECT_EQ(onScreen_.IsSystemCalling(context), true);
    int32_t windowId = 1;
    std::string event = "test";
    sptr<IRemoteOnScreenCallback> callback { nullptr };
    int32_t ret = onScreen_.UnregisterScreenEventCallback(context, windowId, event, callback);
    EXPECT_NE(ret, RET_OK);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}
} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS


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
#include "on_screen_server_test.h"
#include "token_setproc.h"

#undef LOG_TAG
#define LOG_TAG "OnScreenServerTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
using namespace testing::ext;
using namespace Security::AccessToken;
namespace {
OnScreenServer onScreen_;
uint64_t tokenId_ = 0;
const char *PERMISSION_GET_PAGE_CONTENT = "ohos.permission.GET_SCREEN_CONTENT";
const char *PERMISSION_SEND_CONTROL_EVENT = "ohos.permission.SIMULATE_USER_INPUT";
std::mutex g_lockSetToken;
uint64_t g_shellTokenId = 0;
static constexpr int32_t DEFAULT_API_VERSION = 12;
static MockHapToken* g_mock = nullptr;
constexpr int32_t RET_NO_SYSTEM_CALLING = 202;
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
    EXPECT_EQ(0, SetSelfTokenID(GetShellTokenId())); // Set shell token

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

uint64_t NativeTokenGet()
{
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 0,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = nullptr,
        .acls = nullptr,
        .aplStr = "system_basic",
    };

    infoInstance.processName = " DragServerTest";
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
    return tokenId;
}

void OnScreenServerTest::SetUp()
{}

void OnScreenServerTest::TearDown()
{
    onScreen_.handle_.pAlgorithm = nullptr;
}

void OnScreenServerTest::SetUpTestCase()
{
    g_shellTokenId = GetSelfTokenID();
    SetTestEvironment(g_shellTokenId);
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back(PERMISSION_GET_PAGE_CONTENT);
    reqPerm.emplace_back(PERMISSION_SEND_CONTROL_EVENT);
    g_mock = new (std::nothrow) MockHapToken("OnScreenServerTest", reqPerm, true);
    CHKPV(g_mock);
    FI_HILOGI("SetUpTestCase ok.");
}

void OnScreenServerTest::TearDownTestCase()
{
    if (g_mock != nullptr) {
        delete g_mock;
        g_mock = nullptr;
    }
    std::lock_guard<std::mutex> lock(g_lockSetToken);
    g_shellTokenId = 0;
    SetSelfTokenID(g_shellTokenId);
}

void OnScreenServerTest::OnScreenServerTestCallback::OnScreenChange(const std::string& changeInfo)
{
    FI_HILOGI("OnScreenChange");
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
 * @tc.name: GetPageContent002
 * @tc.desc: Test func named GetPageContent
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, GetPageContent002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    ContentOption option;
    PageContent content;
    bool ret = onScreen_.IsSystemCalling(context);
    ASSERT_TRUE(ret);
    ret = onScreen_.CheckPermission(context, PERMISSION_GET_PAGE_CONTENT);
    ASSERT_TRUE(ret);
    int32_t ret1 = onScreen_.GetPageContent(context, option, content);
    EXPECT_TRUE(ret1 >= RET_ERR);
    context.fullTokenId = tokenId_;
    ret = onScreen_.IsSystemCalling(context);
    ASSERT_FALSE(ret);
    ret1 = onScreen_.GetPageContent(context, option, content);
    EXPECT_TRUE(ret1 == RET_NO_SYSTEM_CALLING);
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
 * @tc.name: SendControlEvent002
 * @tc.desc: Test func named  SendControlEvent
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, SendControlEvent002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    bool ret = onScreen_.IsSystemCalling(context);
    ASSERT_TRUE(ret);
    ret = onScreen_.CheckPermission(context, PERMISSION_SEND_CONTROL_EVENT);
    ASSERT_TRUE(ret);
    ControlEvent event;
    event.eventType = EventType::SCROLL_TO_HOOK;
    int32_t ret1 = onScreen_.SendControlEvent(context, event);
    EXPECT_TRUE(ret1 >= RET_ERR);
    context.fullTokenId = tokenId_,
    ret = onScreen_.IsSystemCalling(context);
    ASSERT_FALSE(ret);
    ret1 = onScreen_.SendControlEvent(context, event);
    EXPECT_TRUE(ret1 == RET_NO_SYSTEM_CALLING);
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
        .fullTokenId = (static_cast<uint64_t>(1) << 32),
        .tokenId = 0,
        .uid = 0,
        .pid = 0,
    };
    EXPECT_EQ(onScreen_.IsSystemCalling(context), true);
    context.fullTokenId = 0;
    EXPECT_EQ(onScreen_.IsSystemCalling(context), false);
}

/**
 * @tc.name: IsSystemCalling002
 * @tc.desc: Test func named IsSystemCalling
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, IsSystemCalling002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context {
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    EXPECT_EQ(onScreen_.IsSystemCalling(context), true);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: RegisterScreenEventCallback001
 * @tc.desc: Test func named RegisterScreenEventCallback
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, RegisterScreenEventCallback001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context {
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    EXPECT_EQ(onScreen_.IsSystemCalling(context), true);
    int32_t windowId = 1;
    std::string event = "test";
    sptr<IRemoteOnScreenCallback> callback = new (std::nothrow) OnScreenServerTestCallback();
    ASSERT_NE(callback, nullptr);
    int32_t ret = onScreen_.RegisterScreenEventCallback(context, windowId, event, callback);
    EXPECT_EQ(ret, RET_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}