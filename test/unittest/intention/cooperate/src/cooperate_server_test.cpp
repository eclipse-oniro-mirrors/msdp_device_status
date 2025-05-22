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

#include "accesstoken_kit.h"
#include "gtest/gtest.h"
#include "ipc_skeleton.h"

#include "cooperate_params.h"
#include "cooperate_server.h"
#include "default_params.h"
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
namespace {
int32_t g_userData { 1 };
uint64_t g_tokenID { 0 };
const std::string SYSTEM_BASIC { "system_basic" };
const char* g_basics[] = { "ohos.permission.COOPERATE_MANAGER" };
} // namespace

class CooperateServerTest : public testing::Test {
public:
    CooperateServerTest();
    ~CooperateServerTest() = default;

    void SetUp();
    void TearDown();
    static void SetUpTestCase();
    static void TearDownTestCase();
    static void SetPermission(const std::string &level, const char** perms, size_t permAmount);
    static void RemovePermission();

private:
    Intention intention_ { Intention::COOPERATE };
    std::shared_ptr<TestContext> context_ { nullptr };
    std::shared_ptr<CooperateServer> cooperateServer_ { nullptr };
};

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
    SetPermission(SYSTEM_BASIC, g_basics, sizeof(g_basics) / sizeof(g_basics[0]));
}

void CooperateServerTest::TearDownTestCase()
{
    RemovePermission();
}

void CooperateServerTest::SetPermission(const std::string &level, const char** perms, size_t permAmount)
{
    CALL_DEBUG_ENTER;
    if (perms == nullptr || permAmount == 0) {
        FI_HILOGE("The perms is empty");
        return;
    }

    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = permAmount,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "CooperateServerTest",
        .aplStr = level.c_str(),
    };
    g_tokenID = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(g_tokenID);
    OHOS::Security::AccessToken::AccessTokenKit::AccessTokenKit::ReloadNativeTokenInfo();
}

void CooperateServerTest::RemovePermission()
{
    CALL_DEBUG_ENTER;
    int32_t ret = OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenID);
    if (ret != RET_OK) {
        FI_HILOGE("Failed to remove permission");
        return;
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
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    std::string networkId = "networkId";
    int32_t startDeviceId = 0;
    bool isCheckPermission = true;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->StartCooperate(context, networkId, g_userData, startDeviceId, isCheckPermission));
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
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    std::string networkId = "networkId";
    bool isCheckPermission = true;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->GetCooperateStateAsync(context, networkId, g_userData, isCheckPermission));
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