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

#include "accesstoken_kit.h"
#include "gtest/gtest.h"
#include "ipc_skeleton.h"

#include "cooperate_server.h"
#include "cooperate_server_test.h"
#include "fi_log.h"
#include "nativetoken_kit.h"
#include "test_context.h"
#include "token_setproc.h"

#undef LOG_TAG
#define LOG_TAG "CooperateServerTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
using namespace OHOS::Security::AccessToken;
namespace {
int32_t g_userData { 1 };
uint64_t g_tokenID1 { 5 };
const std::string COOPERATE_ACCESS_PERMISSION { "ohos.permission.COOPERATE_MANAGER" };
std::mutex g_lockSetToken;
uint64_t g_shellTokenId = 0;
static constexpr int32_t DEFAULT_API_VERSION = 12;
static MockHapToken* g_mock = nullptr;
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
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    EXPECT_EQ(callingUid, AppExecFwk::Constants::ROOT_UID);
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

CooperateServerTest::CooperateServerTest()
{
    context_ = std::make_shared<TestContext>();
    cooperateServer_ = std::make_shared<CooperateServer>(context_.get());
}

void CooperateServerTest::SetUp()
{}

void CooperateServerTest::TearDown()
{}

void CooperateServerTest::SetUpTestCase()
{
    g_shellTokenId = GetSelfTokenID();
    SetTestEvironment(g_shellTokenId);
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back(COOPERATE_ACCESS_PERMISSION);
    g_mock = new (std::nothrow) MockHapToken("CooperateServerTest", reqPerm, true);
    CHKPV(g_mock);
    FI_HILOGI("SetUpTestCase ok.");
}

void CooperateServerTest::TearDownTestCase()
{
    std::lock_guard<std::mutex> lock(g_lockSetToken);
    g_shellTokenId = 0;
    if (g_mock != nullptr) {
        delete g_mock;
        g_mock = nullptr;
    }
}

/**
 * @tc.name: EnableTest1
 * @tc.desc: Test func named enable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, EnableTest1, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->EnableCooperate(context, g_userData));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: EnableTest2
 * @tc.desc: Test func named enable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, EnableTest2, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = g_tokenID1,
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->EnableCooperate(context, g_userData));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: DisableTest1
 * @tc.desc: Test func named disable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, DisableTest1, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->DisableCooperate(context, g_userData));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: DisableTest2
 * @tc.desc: Test func named disable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, DisableTest2, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = g_tokenID1,
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->DisableCooperate(context, g_userData));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: StartTest1
 * @tc.desc: Test func named start
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, StartTest1, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    std::string networkId = "networkId";
    int32_t startDeviceId = 0;
    bool isCheckPermission = true;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->StartCooperate(context,
        networkId, g_userData, startDeviceId, isCheckPermission));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: StartTest2
 * @tc.desc: Test func named start
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, StartTest2, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = g_tokenID1,
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    std::string networkId = "networkId";
    int32_t startDeviceId = 0;
    bool isCheckPermission = true;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->StartCooperate(context,
        networkId, g_userData, startDeviceId, isCheckPermission));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: StartWithOptionsTest1
 * @tc.desc: Test func named start
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, StartWithOptionsTest1, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    std::string networkId = "networkId";
    int32_t startDeviceId = 0;
    CooperateOptions options {
            .displayX = 500,
            .displayY = 500,
            .displayId = 1
    };
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->StartCooperateWithOptions(context,
        networkId, g_userData, startDeviceId, options));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: StopCooperateTest1
 * @tc.desc: Test func named stop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, StopCooperateTest1, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    bool isUnchained = true;
    bool isCheckPermission = true;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->StopCooperate(context, g_userData, isUnchained, isCheckPermission));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: StopCooperateTest2
 * @tc.desc: Test func named stop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, StopCooperateTest2, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = g_tokenID1,
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    bool isUnchained = true;
    bool isCheckPermission = true;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->StopCooperate(context, g_userData, isUnchained, isCheckPermission));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: RegisterCooperateListenerTest1
 * @tc.desc: Test func named stop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, RegisterCooperateListenerTest1, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->RegisterCooperateListener(context));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: RegisterCooperateListenerTest2
 * @tc.desc: Test func named stop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, RegisterCooperateListenerTest2, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = g_tokenID1,
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->RegisterCooperateListener(context));
    context_->GetPluginManager().UnloadCooperate();
}
/**
 * @tc.name: UnregisterCooperateListenerTest1
 * @tc.desc: Test func named stop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, UnregisterCooperateListenerTest1, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->UnregisterCooperateListener(context));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: UnregisterCooperateListenerTest2
 * @tc.desc: Test func named stop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, UnregisterCooperateListenerTest2, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = g_tokenID1,
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->UnregisterCooperateListener(context));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: RegisterHotAreaListenerTest1
 * @tc.desc: Test func named stop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, RegisterHotAreaListenerTest1, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    bool isCheckPermission = true;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->RegisterHotAreaListener(context, g_userData, isCheckPermission));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: RegisterHotAreaListenerTest2
 * @tc.desc: Test func named stop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, RegisterHotAreaListenerTest2, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = g_tokenID1,
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    bool isCheckPermission = true;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->RegisterHotAreaListener(context, g_userData, isCheckPermission));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: UnregisterHotAreaListenerTest1
 * @tc.desc: Test func named stop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, UnregisterHotAreaListenerTest1, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->UnregisterHotAreaListener(context));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: UnregisterHotAreaListenerTest2
 * @tc.desc: Test func named stop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, UnregisterHotAreaListenerTest2, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = g_tokenID1,
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->UnregisterHotAreaListener(context));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: RegisterMouseEventListenerTest1
 * @tc.desc: Test func named stop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, RegisterMouseEventListenerTest1, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    std::string networkId = "networkId";
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->RegisterMouseEventListener(context, networkId));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: RegisterMouseEventListenerTest2
 * @tc.desc: Test func named stop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, RegisterMouseEventListenerTest2, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = g_tokenID1,
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    std::string networkId = "networkId";
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->RegisterMouseEventListener(context, networkId));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: UnregisterMouseEventListenerTest1
 * @tc.desc: Test func named stop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, UnregisterMouseEventListenerTest1, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    std::string networkId = "networkId";
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->UnregisterMouseEventListener(context, networkId));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: UnregisterMouseEventListenerTest2
 * @tc.desc: Test func named stop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, UnregisterMouseEventListenerTest2, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = g_tokenID1,
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    std::string networkId = "networkId";
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->UnregisterMouseEventListener(context, networkId));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: GetCooperateStateSyncTest1
 * @tc.desc: Test func named stop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, GetCooperateStateSyncTest1, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    std::string udid = "udid";
    bool state = true;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->GetCooperateStateSync(context, udid, state));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: GetCooperateStateSyncTest2
 * @tc.desc: Test func named stop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, GetCooperateStateSyncTest2, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = g_tokenID1,
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    std::string udid = "udid";
    bool state = true;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->GetCooperateStateSync(context, udid, state));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: GetCooperateStateAsyncTest1
 * @tc.desc: Test func named stop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, GetCooperateStateAsyncTest1, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    std::string networkId = "networkId";
    bool isCheckPermission = true;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->GetCooperateStateAsync(context,
        networkId, g_userData, isCheckPermission));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: GetCooperateStateAsyncTest2
 * @tc.desc: Test func named stop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, GetCooperateStateAsyncTest2, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = g_tokenID1,
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    std::string networkId = "networkId";
    bool isCheckPermission = true;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->GetCooperateStateAsync(context,
        networkId, g_userData, isCheckPermission));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: SetDamplingCoefficientTest1
 * @tc.desc: Test func named SetDamplingCoefficient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, SetDamplingCoefficientTest1, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    uint32_t direction = 0;
    double coefficient = 0;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->SetDamplingCoefficient(context, direction, coefficient));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: SetDamplingCoefficientTest2
 * @tc.desc: Test func named SetDamplingCoefficient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, SetDamplingCoefficientTest2, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = g_tokenID1,
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    uint32_t direction = 0;
    double coefficient = 0;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->SetDamplingCoefficient(context, direction, coefficient));
    context_->GetPluginManager().UnloadCooperate();
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS