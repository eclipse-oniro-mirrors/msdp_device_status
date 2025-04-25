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
    MessageParcel datas;
    MessageParcel reply;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->Enable(context, datas, reply));
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
    MessageParcel datas;
    MessageParcel reply;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->Disable(context, datas, reply));
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
    MessageParcel datas;
    MessageParcel reply;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->Start(context, datas, reply));
}

/**
 * @tc.name: StopTest1
 * @tc.desc: Test func named stop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, StopTest1, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel datas;
    MessageParcel reply;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->Stop(context, datas, reply));
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
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel data;
    MessageParcel reply;
    DefaultParam  param { 1 };
    ASSERT_TRUE(param.Marshalling(data));
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->Enable(context, data, reply));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: AddWatchTest1
 * @tc.desc: Test func named add watch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, AddWatchTest1, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel data;
    MessageParcel reply;
    DefaultParam  param { 1 };
    ASSERT_TRUE(param.Marshalling(data));
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->AddWatch(context, CooperateRequestID::REGISTER_LISTENER, data, reply));
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
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    DefaultParam  param { 1 };
    MessageParcel datas;
    MessageParcel reply;
    param.Marshalling(datas);
    ASSERT_TRUE(param.Marshalling(datas));
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->Disable(context, datas, reply));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: AddWatchTest2
 * @tc.desc: Test func named add watch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, AddWatchTest2, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel data;
    MessageParcel reply;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->AddWatch(
        context, CooperateRequestID::UNKNOWN_COOPERATE_ACTION, data, reply));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: AddWatchTest3
 * @tc.desc: Test func named add watch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, AddWatchTest3, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel data;
    MessageParcel reply;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->AddWatch(
        context, CooperateRequestID::REGISTER_HOTAREA_LISTENER, data, reply));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: AddWatchTest4
 * @tc.desc: Test func named add watch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, AddWatchTest4, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel data;
    MessageParcel reply;
    RegisterEventListenerParam  param { "networkId" };
    param.Marshalling(data);
    ASSERT_TRUE(param.Marshalling(data));
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->AddWatch(
        context, CooperateRequestID::REGISTER_EVENT_LISTENER, data, reply));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: AddWatchTest5
 * @tc.desc: Test func named add watch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, AddWatchTest5, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel data;
    MessageParcel reply;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->AddWatch(
        context, CooperateRequestID::REGISTER_EVENT_LISTENER, data, reply));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: RemoveWatch1
 * @tc.desc: Test func named remove watch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, RemoveWatch1, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel data;
    MessageParcel reply;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->RemoveWatch(
        context, CooperateRequestID::UNREGISTER_LISTENER, data, reply));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: RemoveWatch2
 * @tc.desc: Test func named remove watch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, RemoveWatch2, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel data;
    MessageParcel reply;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->RemoveWatch(
        context, CooperateRequestID::UNKNOWN_COOPERATE_ACTION, data, reply));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: RemoveWatch3
 * @tc.desc: Test func named remove watch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, RemoveWatch3, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel data;
    MessageParcel reply;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->RemoveWatch(
        context, CooperateRequestID::UNREGISTER_HOTAREA_LISTENER, data, reply));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: RemoveWatch4
 * @tc.desc: Test func named remove watch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, RemoveWatch4, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel data;
    MessageParcel reply;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->RemoveWatch(
        context, CooperateRequestID::UNREGISTER_EVENT_LISTENER, data, reply));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: RemoveWatch5
 * @tc.desc: Test func named remove watch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, RemoveWatch5, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel data;
    MessageParcel reply;
    UnregisterEventListenerParam param { "networkId" };
    param.Marshalling(data);
    ASSERT_TRUE(param.Marshalling(data));
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->RemoveWatch(
        context, CooperateRequestID::UNREGISTER_EVENT_LISTENER, data, reply));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: SetParam
 * @tc.desc: Test func named set param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, SetParam, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel data;
    MessageParcel reply;
    ASSERT_NO_FATAL_FAILURE(
        cooperateServer_->SetParam(context, CooperateRequestID::SET_DAMPLING_COEFFICIENT, data, reply));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: SetParam1
 * @tc.desc: Test func named set param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, SetParam1, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel data;
    MessageParcel reply;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->SetParam(
        context, CooperateRequestID::REGISTER_LISTENER, data, reply));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: SetParam2
 * @tc.desc: Test func named set param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, SetParam2, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    RemovePermission();
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel data;
    MessageParcel reply;
    uint32_t direction = 0;
    double coefficient = 0;
    SetDamplingCoefficientParam param { direction, coefficient };
    ASSERT_TRUE(param.Marshalling(data));
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->SetParam(
        context, CooperateRequestID::SET_DAMPLING_COEFFICIENT, data, reply));
    context_->GetPluginManager().UnloadCooperate();
}
/**
 * @tc.name: GetParam1
 * @tc.desc: Test func named get param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, GetParam1, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel data;
    MessageParcel reply;
    GetCooperateStateParam param {1, "networkId", true};
    param.Marshalling(data);
    ASSERT_TRUE(param.Marshalling(data));
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->GetParam(
        context, CooperateRequestID::GET_COOPERATE_STATE, data, reply));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: GetParam2
 * @tc.desc: Test func named get param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, GetParam2, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel data;
    MessageParcel reply;
    GetCooperateStateSyncParam param { "networkId" };
    param.Marshalling(data);
    ASSERT_TRUE(param.Marshalling(data));
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->GetParam(
        context, CooperateRequestID::GET_COOPERATE_STATE_SYNC, data, reply));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: GetParam3
 * @tc.desc: Test func named get param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, GetParam3, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel data;
    MessageParcel reply;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->GetParam(
        context, CooperateRequestID::GET_COOPERATE_STATE_SYNC, data, reply));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: GetParam4
 * @tc.desc: Test func named get param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, GetParam4, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel data;
    MessageParcel reply;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->GetParam(
        context, CooperateRequestID::SET_DAMPLING_COEFFICIENT, data, reply));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: StopTest2
 * @tc.desc: Test func named stop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, StopTest2, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    StopCooperateParam param {1, false, true};
    MessageParcel data;
    MessageParcel reply;
    param.Marshalling(data);
    ASSERT_TRUE(param.Marshalling(data));
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->Stop(context, data, reply));
    context_->GetPluginManager().UnloadCooperate();
}

/**
 * @tc.name: ControlTest1
 * @tc.desc: Test func named control
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, ControlTest1, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel data;
    MessageParcel reply;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->Control(
        context, CooperateRequestID::UNKNOWN_COOPERATE_ACTION, data, reply));
}

/**
 * @tc.name: EnableTest3
 * @tc.desc: Test func named enable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, EnableTest3, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    RemovePermission();
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel datas;
    MessageParcel reply;
    cooperateServer_->Enable(context, datas, reply);
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->Enable(context, datas, reply));
}

/**
 * @tc.name: DisableTest3
 * @tc.desc: Test func named Disable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, DisableTest3, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    RemovePermission();
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel datas;
    MessageParcel reply;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->Disable(context, datas, reply));
}

/**
 * @tc.name: StartTest2
 * @tc.desc: Test func named enable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, StartTest2, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    RemovePermission();
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel datas;
    MessageParcel reply;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->Start(context, datas, reply));
}

/**
 * @tc.name: StopTest3
 * @tc.desc: Test func named enable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, StopTest3, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    RemovePermission();
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel datas;
    MessageParcel reply;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->Stop(context, datas, reply));
}

/**
 * @tc.name: AddWatchTest6
 * @tc.desc: Test func named enable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateServerTest, AddWatchTest6, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    RemovePermission();
    CallingContext context {
        .intention = intention_,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel datas;
    MessageParcel reply;
    ASSERT_NO_FATAL_FAILURE(cooperateServer_->AddWatch(context, REGISTER_LISTENER, datas, reply));
    context_->GetPluginManager().UnloadCooperate();
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS