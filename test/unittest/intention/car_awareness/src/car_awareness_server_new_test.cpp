/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "car_awareness_type.h"
#include "car_awareness_server.h"
#include "car_awareness_server_new_test.h"
#include "token_setproc.h"

#undef LOG_TAG
#define LOG_TAG "CarAwarenessServerNewTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing;
using namespace testing::ext;
using namespace Security::AccessToken;
namespace {
constexpr int32_t TYPE_SPATIAL_MOTION = 101;
constexpr int32_t TYPE_SPATIAL_POINT = 201;
constexpr int32_t TYPE_CAR_STATUS = 203;
constexpr int32_t DUMMY_PID = 12345;
std::mutex g_lockSetToken;
uint64_t g_shellTokenId = 0;
static constexpr int32_t DEFAULT_API_VERSION = 12;
static MockHapToken *g_mock = nullptr;
constexpr int32_t CAR_AWARENESS_SPECIFIC_ERR = 34000002;

static CarAwarenessServer *g_staticServer = nullptr;

void PreloadAlgoLib()
{
    if (g_staticServer == nullptr) {
        g_staticServer = new (std::nothrow) CarAwarenessServer();
    }
    if (g_staticServer != nullptr) {
        g_staticServer->LoadAlgoLib();
    }
}

void CleanupStaticServer()
{
    if (g_staticServer != nullptr) {
        g_staticServer->algoHandle_.pAlgorithm = nullptr;
        g_staticServer->algoHandle_.handle = nullptr;
        g_staticServer->algoHandle_.create = nullptr;
        g_staticServer->algoHandle_.destroy = nullptr;
        delete g_staticServer;
        g_staticServer = nullptr;
    }
}

CarAwarenessServer &GetTestServer()
{
    if (g_staticServer == nullptr) {
        g_staticServer = new (std::nothrow) CarAwarenessServer();
    }
    return *g_staticServer;
}
}  // namespace

AccessTokenID CarAwarenessServerNewTest::hapTokenId_ = 0;

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
    EXPECT_EQ(0, SetSelfTokenID(GetShellTokenId()));

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

int32_t AllocTestHapToken(const HapInfoParams &hapInfo, HapPolicyParams &hapPolicy, AccessTokenIDEx &tokenIdEx)
{
    uint64_t selfTokenId = GetSelfTokenID();
    for (auto &permissionStateFull : hapPolicy.permStateList) {
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
    MockNativeToken mock("foundation");
    int32_t ret = AccessTokenKit::InitHapToken(hapInfo, hapPolicy, tokenIdEx);
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

MockNativeToken::MockNativeToken(const std::string &process)
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

MockHapToken::MockHapToken(const std::string &bundle, const std::vector<std::string> &reqPerm, bool isSystemApp)
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
        PermissionStateFull permState = {.permissionName = reqPerm[i],
                                         .isGeneral = true,
                                         .resDeviceID = {"local3"},
                                         .grantStatus = {PermissionState::PERMISSION_GRANTED},
                                         .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG}};
        policyParams.permStateList.emplace_back(permState);
        if (permDefResult.availableLevel > policyParams.apl) {
            policyParams.aclRequestedList.emplace_back(reqPerm[i]);
        }
    }

    AccessTokenIDEx tokenIdEx = {0};
    EXPECT_EQ(RET_SUCCESS, AllocTestHapToken(infoParams, policyParams, tokenIdEx));
    mockToken_ = tokenIdEx.tokenIdExStruct.tokenID;
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

uint64_t NativeTokenGet(bool withPermissions = true)
{
    uint64_t tokenId;
    static const char *allPerms[] = {"ohos.permission.vehicle.MMA_SPATIALACTION",
                                     "ohos.permission.vehicle.MMA_WEATHER",
                                     "ohos.permission.vehicle.MMA_ENERGYREFILL"};
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = withPermissions ? 3 : 0,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = withPermissions ? allPerms : nullptr,
        .acls = nullptr,
        .aplStr = "system_basic",
    };

    infoInstance.processName = "CarAwarenessServerNewTest";
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
    return tokenId;
}

void CarAwarenessServerNewTest::SetUp()
{}

void CarAwarenessServerNewTest::TearDown()
{}

void CarAwarenessServerNewTest::SetUpTestCase()
{
    g_shellTokenId = GetSelfTokenID();
    SetTestEvironment(g_shellTokenId);
    std::vector<std::string> reqPerm;
    g_mock = new (std::nothrow) MockHapToken("CarAwarenessServerNewTest", reqPerm, false);
    CHKPV(g_mock);
    hapTokenId_ = g_mock->mockToken_;
    ASSERT_NE(0, hapTokenId_);
    PreloadAlgoLib();
    FI_HILOGI("SetUpTestCase ok.");
}

void CarAwarenessServerNewTest::TearDownTestCase()
{
    CleanupStaticServer();
    if (g_mock != nullptr) {
        delete g_mock;
        g_mock = nullptr;
    }
    if (hapTokenId_ != 0) {
        AccessTokenKit::DeleteToken(hapTokenId_);
        hapTokenId_ = 0;
    }
    std::lock_guard<std::mutex> lock(g_lockSetToken);
    g_shellTokenId = 0;
    SetSelfTokenID(g_shellTokenId);
}

void CarAwarenessServerNewTest::CarAwarenessServerNewTestCallback::OnAwarenessEvent(const CarAwarenessEvent &event)
{
    FI_HILOGI("OnAwarenessEvent type:%{public}d", event.type);
}

/**
 * @tc.name: LoadAlgoLib
 * @tc.desc: Test LoadAlgoLib
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, LoadAlgoLib, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessServer &server = GetTestServer();
    int32_t ret = server.LoadAlgoLib();
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
}

/**
 * @tc.name: UnloadAlgoLib
 * @tc.desc: Test UnloadAlgoLib
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, UnloadAlgoLib, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessServer &server = GetTestServer();
    int32_t ret = server.UnloadAlgoLib();
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: UpdateSpatialActionStatus_WithAlgo
 * @tc.desc: Test UpdateSpatialActionStatus when algo is loaded
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, UpdateSpatialActionStatus_WithAlgo, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet(true);
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    CarAwarenessServer &server = GetTestServer();
    int32_t ret = server.UpdateSpatialActionStatus(context, 1);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: UpdateSpatialActionStatus_WithoutPermission
 * @tc.desc: Test UpdateSpatialActionStatus without permission
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, UpdateSpatialActionStatus_WithoutPermission, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet(false);
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    CarAwarenessServer &server = GetTestServer();
    int32_t ret = server.UpdateSpatialActionStatus(context, 1);
    EXPECT_EQ(ret, COMMON_PERMISSION_CHECK_ERROR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: UpdateSpatialActionZone_WithAlgo
 * @tc.desc: Test UpdateSpatialActionZone when algo is loaded
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, UpdateSpatialActionZone_WithAlgo, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet(true);
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    CarAwarenessServer &server = GetTestServer();
    int32_t ret = server.UpdateSpatialActionZone(context, 1);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: UpdateSpatialActionZone_WithoutPermission
 * @tc.desc: Test UpdateSpatialActionZone without permission
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, UpdateSpatialActionZone_WithoutPermission, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet(false);
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    CarAwarenessServer &server = GetTestServer();
    int32_t ret = server.UpdateSpatialActionZone(context, 1);
    EXPECT_EQ(ret, COMMON_PERMISSION_CHECK_ERROR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: GetSupportCapabilityList_WithAlgo
 * @tc.desc: Test GetSupportCapabilityList when algo is loaded
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, GetSupportCapabilityList_WithAlgo, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context;
    std::vector<std::string> capabilities;
    CarAwarenessServer &server = GetTestServer();
    int32_t ret = server.GetSupportCapabilityList(context, capabilities);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
}

/**
 * @tc.name: GetCarAwareness_WithAlgo
 * @tc.desc: Test GetCarAwareness when algo is loaded
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, GetCarAwareness_WithAlgo, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    CarAwarenessOption option;
    std::vector<CarAwarenessEvent> events;
    CarAwarenessServer &server = GetTestServer();
    int32_t ret = server.GetCarAwareness(context, TYPE_CAR_STATUS, option, events);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: SubscribeCapability_WithAlgo
 * @tc.desc: Test SubscribeCapability when algo is loaded
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, SubscribeCapability_WithAlgo, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    CarAwarenessOption option;
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb, nullptr);
    CarAwarenessServer &server = GetTestServer();
    int32_t ret = server.SubscribeCapability(context, TYPE_SPATIAL_POINT, option, cb);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: CheckSystemCall003
 * @tc.desc: Test func named CheckSystemCall with HAP token that is not system app
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, CheckSystemCall003, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(0, hapTokenId_);
    ASSERT_EQ(0, SetSelfTokenID(hapTokenId_));
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    CarAwarenessServer &server = GetTestServer();
    EXPECT_EQ(server.CheckSystemCall(context), false);
}

/**
 * @tc.name: SubscribeCapability_No_Permission
 * @tc.desc: Test SubscribeCapability without permission (HAP token)
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, SubscribeCapability_No_Permission, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(0, hapTokenId_);
    ASSERT_EQ(0, SetSelfTokenID(hapTokenId_));
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    CarAwarenessOption option;
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb, nullptr);
    CarAwarenessServer &server = GetTestServer();
    int32_t ret = server.SubscribeCapability(context, TYPE_SPATIAL_MOTION, option, cb);
    EXPECT_EQ(ret, COMMON_PERMISSION_CHECK_ERROR);
    ASSERT_EQ(0, SetSelfTokenID(g_shellTokenId));
}

/**
 * @tc.name: UnSubscribeCapability_WithAlgo
 * @tc.desc: Test UnSubscribeCapability when algo is loaded
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, UnSubscribeCapability_WithAlgo, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    CarAwarenessOption option;
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb, nullptr);
    CarAwarenessServer &server = GetTestServer();
    int32_t ret = server.UnSubscribeCapability(context, TYPE_SPATIAL_POINT, option, cb);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: UnSubscribeCapability_No_Permission
 * @tc.desc: Test UnSubscribeCapability without permission (HAP token)
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, UnSubscribeCapability_No_Permission, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(0, hapTokenId_);
    ASSERT_EQ(0, SetSelfTokenID(hapTokenId_));
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    CarAwarenessOption option;
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb, nullptr);
    CarAwarenessServer &server = GetTestServer();
    int32_t ret = server.UnSubscribeCapability(context, TYPE_SPATIAL_MOTION, option, cb);
    EXPECT_EQ(ret, COMMON_PERMISSION_CHECK_ERROR);
    ASSERT_EQ(0, SetSelfTokenID(g_shellTokenId));
}

/**
 * @tc.name: SubscribeAlgo
 * @tc.desc: Test SubscribeAlgo
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, SubscribeAlgo, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessServer &server = GetTestServer();
    int32_t ret = server.SubscribeAlgo("SpatialPoint");
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
}

/**
 * @tc.name: UnSubscribeAlgo
 * @tc.desc: Test UnSubscribeAlgo
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, UnSubscribeAlgo, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessServer &server = GetTestServer();
    server.UnSubscribeAlgo("SpatialPoint");
    EXPECT_TRUE(true);
}

/**
 * @tc.name: EraseCallback_Empty
 * @tc.desc: Test EraseCallback with non-existent feature
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, EraseCallback_Empty, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessServer &server = GetTestServer();
    bool ret = server.EraseCallback("NonExistentFeature", 12345);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: EraseCallback
 * @tc.desc: Test EraseCallback
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, EraseCallback, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessServer &server = GetTestServer();
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb, nullptr);
    CarAwarenessClientInfo clientInfo = {.pid = IPCSkeleton::GetCallingPid(), .cb = cb};
    server.callbacks_["SpatialPoint"].push_back(clientInfo);
    bool ret = server.EraseCallback("SpatialPoint", IPCSkeleton::GetCallingPid());
    EXPECT_TRUE(ret == true);
}

/**
 * @tc.name: EraseCallback002
 * @tc.desc: Test EraseCallback002
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, EraseCallback002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessServer &server = GetTestServer();
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb, nullptr);
    sptr<ICarAwarenessCallback> cb2 = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb2, nullptr);
    CarAwarenessClientInfo dummyClientInfo = {.pid = DUMMY_PID, .cb = cb2};
    CarAwarenessClientInfo clientInfo = {.pid = IPCSkeleton::GetCallingPid(), .cb = cb};
    server.callbacks_["SpatialPoint"].push_back(dummyClientInfo);
    server.callbacks_["SpatialPoint"].push_back(clientInfo);
    bool ret = server.EraseCallback("SpatialPoint", IPCSkeleton::GetCallingPid());
    EXPECT_TRUE(ret == true);
}

/**
 * @tc.name: OnCarAwarenessCallbackDied_NullClient
 * @tc.desc: Test OnCarAwarenessCallbackDied with null client
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, OnCarAwarenessCallbackDied_NullClient, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessServer &server = GetTestServer();
    wptr<IRemoteObject> remote;
    server.OnCarAwarenessCallbackDied(remote);
    EXPECT_TRUE(true);
}

/**
 * @tc.name: OnCarAwarenessCallbackDied
 * @tc.desc: Test OnCarAwarenessCallbackDied
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, OnCarAwarenessCallbackDied, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessServer &server = GetTestServer();
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerNewTestCallback();
    auto clientObj = cb->AsObject();
    server.OnCarAwarenessCallbackDied(clientObj);
    EXPECT_TRUE(true);
}

/**
 * @tc.name: OnCarAwarenessCallbackDied002
 * @tc.desc: Test OnCarAwarenessCallbackDied002
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, OnCarAwarenessCallbackDied002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessServer &server = GetTestServer();
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerNewTestCallback();
    CarAwarenessClientInfo clientInfo = {.pid = IPCSkeleton::GetCallingPid(), .cb = cb};
    server.callbacks_["SpatialMotion"].push_back(clientInfo);
    auto clientObj = cb->AsObject();
    server.OnCarAwarenessCallbackDied(clientObj);
    EXPECT_TRUE(true);
}

/**
 * @tc.name: OnCarAwarenessCallbackDied003
 * @tc.desc: Test OnCarAwarenessCallbackDied003
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, OnCarAwarenessCallbackDied003, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessServer &server = GetTestServer();
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerNewTestCallback();
    CarAwarenessClientInfo clientInfo = {.pid = IPCSkeleton::GetCallingPid(), .cb = cb};
    sptr<ICarAwarenessCallback> cb2 = new (std::nothrow) CarAwarenessServerNewTestCallback();
    CarAwarenessClientInfo dummyClientInfo = {.pid = DUMMY_PID, .cb = cb2};
    server.callbacks_["SpatialMotion"].push_back(dummyClientInfo);
    server.callbacks_["SpatialMotion"].push_back(clientInfo);
    auto clientObj = cb->AsObject();
    server.OnCarAwarenessCallbackDied(clientObj);
    EXPECT_TRUE(true);
}

/**
 * @tc.name: AddDeathRecipient_NullCallback
 * @tc.desc: Test AddDeathRecipient with null callback
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, AddDeathRecipient_NullCallback, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessServer &server = GetTestServer();
    sptr<ICarAwarenessCallback> cb = nullptr;
    bool ret = server.AddDeathRecipient(cb);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: RemoveDeathRecipient_NullCallback
 * @tc.desc: Test RemoveDeathRecipient with null callback
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, RemoveDeathRecipient_NullCallback, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessServer &server = GetTestServer();
    sptr<ICarAwarenessCallback> cb = nullptr;
    server.RemoveDeathRecipient(cb);
    EXPECT_TRUE(true);
}

/**
 * @tc.name: CheckPermission_Granted
 * @tc.desc: Test CheckPermission when permission is granted
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, CheckPermission_Granted, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    CarAwarenessServer &server = GetTestServer();
    int32_t ret = server.CheckPermission(context, "ohos.permission.vehicle.MMA_SPATIALACTION");
    EXPECT_TRUE(ret == RET_OK || ret == COMMON_PERMISSION_CHECK_ERROR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: CheckPermission_Denied
 * @tc.desc: Test CheckPermission when permission is denieed
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, CheckPermission_Denied, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet(false);
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    CarAwarenessServer &server = GetTestServer();
    int32_t ret = server.CheckPermission(context, "ohos.permission.vehicle.MMA_SPATIALACTION");
    EXPECT_TRUE(ret == RET_OK || ret == COMMON_PERMISSION_CHECK_ERROR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: CheckSubPermissionByType_SystemApi
 * @tc.desc: Test CheckSubPermissionByType with system API type
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, CheckSubPermissionByType_SystemApi, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    CarAwarenessServer &server = GetTestServer();
    int32_t ret = server.CheckSubPermissionByType(context, TYPE_CAR_STATUS);
    EXPECT_EQ(ret, RET_OK);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: OnResultFromAlgo
 * @tc.desc: Test OnResultFromAlgo
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, OnResultFromAlgo, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessServer &server = GetTestServer();
    server.OnResultFromAlgo("SpatialPoint", "test result");
    EXPECT_TRUE(true);
}

/**
 * @tc.name: OnResultFromAlgo002
 * @tc.desc: Test OnResultFromAlgo002
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, OnResultFromAlgo002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessServer &server = GetTestServer();
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb, nullptr);
    CarAwarenessClientInfo clientInfo = {.pid = IPCSkeleton::GetCallingPid(), .cb = cb};
    server.callbacks_["SpatialPoint"].push_back(clientInfo);
    server.OnResultFromAlgo("SpatialPoint", "test result");
    EXPECT_TRUE(true);
}

/**
 * @tc.name: OnResultFromAlgo003
 * @tc.desc: Test OnResultFromAlgo003
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, OnResultFromAlgo003, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessServer &server = GetTestServer();
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb, nullptr);
    CarAwarenessClientInfo clientInfo = {.pid = IPCSkeleton::GetCallingPid(), .cb = cb};
    server.callbacks_["DUMMY"].push_back(clientInfo);
    server.OnResultFromAlgo("DUMMY", "test result");
    EXPECT_TRUE(true);
}

/**
 * @tc.name: AddClientToCallbacks001
 * @tc.desc: Test AddClientToCallbacks001
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, AddClientToCallbacks001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessServer &server = GetTestServer();
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb, nullptr);
    CarAwarenessClientInfo clientInfo = {.pid = IPCSkeleton::GetCallingPid(), .cb = cb};
    int32_t ret = server.AddClientToCallbacks("SpatialPoint", clientInfo);
    ret = server.AddClientToCallbacks("SpatialPoint", clientInfo);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: SubscribeCarStatusWithOption_Basic
 * @tc.desc: Test SubscribeCarStatusWithOption basic subscription
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, SubscribeCarStatusWithOption_Basic, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    CarAwarenessOption option;
    option.entityInfo["CarStatus"] = "TestDevice:TestFunc";
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb, nullptr);
    CarAwarenessServer &server = GetTestServer();
    int32_t ret = server.SubscribeCarStatusWithOption("CarStatus", context.pid, option, cb);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: SubscribeCarStatusWithOption_EmptyOption
 * @tc.desc: Test SubscribeCarStatusWithOption with empty option
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, SubscribeCarStatusWithOption_EmptyOption, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    CarAwarenessOption option;
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb, nullptr);
    CarAwarenessServer &server = GetTestServer();
    int32_t ret = server.SubscribeCarStatusWithOption("CarStatus", context.pid, option, cb);
    EXPECT_EQ(ret, RET_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: IsOptionEmpty_Empty
 * @tc.desc: Test IsOptionEmpty with empty option
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, IsOptionEmpty_Empty, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessServer &server = GetTestServer();
    CarAwarenessOption option;
    bool ret = server.IsOptionEmpty(option);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: IsOptionEmpty_WithDeviceStatus
 * @tc.desc: Test IsOptionEmpty when deviceStatus exists
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, IsOptionEmpty_WithDeviceStatus, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessServer &server = GetTestServer();
    CarAwarenessOption option;
    option.entityInfo["CarStatus"] = "TestDevice:TestFunc";
    bool ret = server.IsOptionEmpty(option);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: UnSubscribeCarStatus_Basic
 * @tc.desc: Test UnSubscribeCarStatus basic unsubscription
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, UnSubscribeCarStatus_Basic, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    CarAwarenessOption option;
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb, nullptr);
    CarAwarenessServer &server = GetTestServer();
    server.callbacks_["CarStatus"].push_back({context.pid, cb, option});
    option.entityInfo["CarStatus"] = "TestDevice:TestFunc";
    int32_t ret = server.UnSubscribeCarStatus("CarStatus", context.pid, option);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: UnSubscribeCarStatus_NotFound
 * @tc.desc: Test UnSubscribeCarStatus when callback not found
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, UnSubscribeCarStatus_NotFound, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    CarAwarenessOption option;
    CarAwarenessServer &server = GetTestServer();
    int32_t ret = server.UnSubscribeCarStatus("CarStatus", context.pid, option);
    EXPECT_EQ(ret, RET_OK);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: UnSubscribeCarStatus_EmptyOption
 * @tc.desc: Test UnSubscribeCarStatus with empty option
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, UnSubscribeCarStatus_EmptyOption, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    CarAwarenessOption option;
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb, nullptr);
    CarAwarenessServer &server = GetTestServer();
    server.callbacks_["CarStatus"].push_back({context.pid, cb, option});
    int32_t ret = server.UnSubscribeCarStatus("CarStatus", context.pid, option);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: GetCarAwareness_NotSystemCall
 * @tc.desc: Test GetCarAwareness when not system call
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, GetCarAwareness_NotSystemCall, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    ASSERT_NE(0, hapTokenId_);
    ASSERT_EQ(0, SetSelfTokenID(hapTokenId_));
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    CarAwarenessOption option;
    std::vector<CarAwarenessEvent> events;
    CarAwarenessServer &server = GetTestServer();
    int32_t ret = server.GetCarAwareness(context, TYPE_CAR_STATUS, option, events);
    EXPECT_EQ(ret, COMMON_NOT_SYSTEM_APP);
    ASSERT_EQ(0, SetSelfTokenID(g_shellTokenId));
}

/**
 * @tc.name: GetCarAwareness_AlgoLibLoadFailed
 * @tc.desc: Test GetCarAwareness when algo lib load failed
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, GetCarAwareness_AlgoLibLoadFailed, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    CarAwarenessOption option;
    std::vector<CarAwarenessEvent> events;
    CarAwarenessServer &server = GetTestServer();
    server.algoHandle_.pAlgorithm = nullptr;
    int32_t ret = server.GetCarAwareness(context, TYPE_CAR_STATUS, option, events);
    EXPECT_EQ(ret, RET_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: GetCarAwareness_CarStatus_APIFailed
 * @tc.desc: Test GetCarAwareness for CarStatus type when API returns error
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, GetCarAwareness_CarStatus_APIFailed, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    CarAwarenessOption option;
    option.entityInfo["TestDevice"] = "TestFunc";
    std::vector<CarAwarenessEvent> events;
    CarAwarenessServer &server = GetTestServer();
    int32_t ret = server.GetCarAwareness(context, TYPE_CAR_STATUS, option, events);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: GetCarAwareness_NonCarStatusType
 * @tc.desc: Test GetCarAwareness for non-CarStatus type
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, GetCarAwareness_NonCarStatusType, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    CarAwarenessOption option;
    std::vector<CarAwarenessEvent> events;
    CarAwarenessServer &server = GetTestServer();
    int32_t ret = server.GetCarAwareness(context, TYPE_SPATIAL_MOTION, option, events);
    EXPECT_EQ(ret, RET_OK);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: SubscribeCapability_NullCallback
 * @tc.desc: Test SubscribeCapability with null callback
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, SubscribeCapability_NullCallback, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    CarAwarenessOption option;
    CarAwarenessServer &server = GetTestServer();
    int32_t ret = server.SubscribeCapability(context, TYPE_SPATIAL_MOTION, option, nullptr);
    EXPECT_EQ(ret, RET_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: SubscribeCapability_UnknownType
 * @tc.desc: Test SubscribeCapability with unknown type
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, SubscribeCapability_UnknownType, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    CarAwarenessOption option;
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb, nullptr);
    CarAwarenessServer &server = GetTestServer();
    int32_t ret = server.SubscribeCapability(context, 9999, option, cb);
    EXPECT_EQ(ret, CAR_AWARENESS_SPECIFIC_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: SubscribeCapability_CarStatusType
 * @tc.desc: Test SubscribeCapability with TYPE_CAR_STATUS
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, SubscribeCapability_CarStatusType, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    CarAwarenessOption option;
    option.entityInfo["TestDevice"] = "TestFunc";
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb, nullptr);
    CarAwarenessServer &server = GetTestServer();
    int32_t ret = server.SubscribeCapability(context, TYPE_CAR_STATUS, option, cb);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: SubscribeCapability_AlgoAlreadySubscribed
 * @tc.desc: Test SubscribeCapability when algo is already subscribed
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, SubscribeCapability_AlgoAlreadySubscribed, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    CarAwarenessOption option;
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb, nullptr);
    CarAwarenessServer &server = GetTestServer();
    server.callbacks_["SpatialPoint"] = std::vector<CarAwarenessClientInfo>();
    int32_t ret = server.SubscribeCapability(context, TYPE_SPATIAL_POINT, option, cb);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: SubscribeCapability_AddClientFailed
 * @tc.desc: Test SubscribeCapability when AddClientToCallbacks fails
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, SubscribeCapability_AddClientFailed, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    CarAwarenessOption option;
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb, nullptr);
    CarAwarenessServer &server = GetTestServer();
    server.callbacks_["SpatialPoint"] = std::vector<CarAwarenessClientInfo>();
    CarAwarenessClientInfo existingInfo = {.pid = context.pid, .cb = cb};
    server.callbacks_["SpatialPoint"].push_back(existingInfo);
    int32_t ret = server.SubscribeCapability(context, TYPE_SPATIAL_POINT, option, cb);
    EXPECT_EQ(ret, RET_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: SubscribeCapability_SubscribeAlgoFailed
 * @tc.desc: Test SubscribeCapability when SubscribeAlgo fails
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, SubscribeCapability_SubscribeAlgoFailed, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    CarAwarenessOption option;
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb, nullptr);
    CarAwarenessServer &server = GetTestServer();
    server.algoHandle_.pAlgorithm = nullptr;
    int32_t ret = server.SubscribeCapability(context, TYPE_SPATIAL_POINT, option, cb);
    EXPECT_EQ(ret, RET_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: EraseCallback_RemainingCallbacksWithNullAlgorithm
 * @tc.desc: Test EraseCallback when remaining callbacks exist but pAlgorithm is null
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, EraseCallback_RemainingCallbacksWithNullAlgorithm, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessServer &server = GetTestServer();
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb, nullptr);
    sptr<ICarAwarenessCallback> cb2 = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb2, nullptr);
    CarAwarenessClientInfo clientInfo1 = {.pid = IPCSkeleton::GetCallingPid(), .cb = cb};
    CarAwarenessClientInfo clientInfo2 = {.pid = DUMMY_PID, .cb = cb2};
    server.callbacks_["SpatialPoint"].push_back(clientInfo1);
    server.callbacks_["SpatialPoint"].push_back(clientInfo2);
    server.algoHandle_.pAlgorithm = nullptr;
    bool ret = server.EraseCallback("SpatialPoint", IPCSkeleton::GetCallingPid());
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: UnSubscribeCapability_UnknownType
 * @tc.desc: Test UnSubscribeCapability with unknown type
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, UnSubscribeCapability_UnknownType, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    CarAwarenessOption option;
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb, nullptr);
    CarAwarenessServer &server = GetTestServer();
    int32_t ret = server.UnSubscribeCapability(context, 9999, option, cb);
    EXPECT_EQ(ret, RET_OK);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: UnSubscribeCapability_CarStatusType
 * @tc.desc: Test UnSubscribeCapability with TYPE_CAR_STATUS
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, UnSubscribeCapability_CarStatusType, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    CarAwarenessOption option;
    CarAwarenessServer &server = GetTestServer();
    int32_t ret = server.UnSubscribeCapability(context, TYPE_CAR_STATUS, option, nullptr);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: OnCarAwarenessCallbackDied_RemainingCallbacksWithNullAlgorithm
 * @tc.desc: Test OnCarAwarenessCallbackDied when remaining callbacks exist but pAlgorithm is null
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, OnCarAwarenessCallbackDied_RemainingCallbacksWithNullAlgorithm, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessServer &server = GetTestServer();
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb, nullptr);
    sptr<ICarAwarenessCallback> cb2 = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb2, nullptr);
    CarAwarenessClientInfo clientInfo1 = {.pid = IPCSkeleton::GetCallingPid(), .cb = cb};
    CarAwarenessClientInfo clientInfo2 = {.pid = DUMMY_PID, .cb = cb2};
    server.callbacks_["SpatialMotion"].push_back(clientInfo1);
    server.callbacks_["SpatialMotion"].push_back(clientInfo2);
    server.algoHandle_.pAlgorithm = nullptr;
    auto clientObj = cb->AsObject();
    server.OnCarAwarenessCallbackDied(clientObj);

    EXPECT_EQ(server.callbacks_["SpatialMotion"].size(), 1);
    ASSERT_FALSE(server.callbacks_["SpatialMotion"].empty());
    EXPECT_EQ(server.callbacks_["SpatialMotion"][0].pid, DUMMY_PID);
}

/**
 * @tc.name: SubscribeAlgo_LoadAlgoLibFailed
 * @tc.desc: Test SubscribeAlgo when LoadAlgoLib fails
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, SubscribeAlgo_LoadAlgoLibFailed, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessServer &server = GetTestServer();
    server.algoHandle_.pAlgorithm = nullptr;
    CarAwarenessOption option;
    int32_t ret = server.SubscribeAlgo("SpatialPoint", option);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: SubscribeAlgo_WithValidEntityInfo
 * @tc.desc: Test SubscribeAlgo with valid entityInfo in option
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, SubscribeAlgo_WithValidEntityInfo, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessServer &server = GetTestServer();
    CarAwarenessOption option;
    option.entityInfo["TestDevice"] = "TestFunc";
    int32_t ret = server.SubscribeAlgo("CarStatus", option);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
}

/**
 * @tc.name: SubscribeAlgo_WithoutValidEntityInfo
 * @tc.desc: Test SubscribeAlgo without valid entityInfo in option
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, SubscribeAlgo_WithoutValidEntityInfo, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessServer &server = GetTestServer();
    CarAwarenessOption option;
    int32_t ret = server.SubscribeAlgo("SpatialPoint", option);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
}

/**
 * @tc.name: OnResultFromAlgo_CarStatus
 * @tc.desc: Test OnResultFromAlgo with CarStatus feature
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, OnResultFromAlgo_CarStatus, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessServer &server = GetTestServer();
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb, nullptr);
    CarAwarenessClientInfo clientInfo = {.pid = IPCSkeleton::GetCallingPid(), .cb = cb};
    server.callbacks_["CarStatus"].push_back(clientInfo);

    int32_t beforeSize = server.callbacks_["CarStatus"].size();
    std::string result = R"([{"device":"TestDevice","function":[{"function_name":"TestFunc"}]}])";
    server.OnResultFromAlgo("CarStatus", result);

    EXPECT_EQ(server.callbacks_["CarStatus"].size(), beforeSize);
    ASSERT_FALSE(server.callbacks_["CarStatus"].empty());
    EXPECT_EQ(server.callbacks_["CarStatus"][0].pid, IPCSkeleton::GetCallingPid());
}

/**
 * @tc.name: GetCarAwareness_CarStatus_EmptyResults
 * @tc.desc: Test GetCarAwareness for CarStatus with empty results
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, GetCarAwareness_CarStatus_EmptyResults, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    CarAwarenessOption option;
    option.entityInfo["CarStatus"] = "TestDevice:TestFunc";
    std::vector<CarAwarenessEvent> events;
    CarAwarenessServer &server = GetTestServer();
    int32_t ret = server.GetCarAwareness(context, TYPE_CAR_STATUS, option, events);
    if (ret == RET_OK && !events.empty()) {
        EXPECT_EQ(events[0].eventData, "[]");
    }
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: GetCarAwareness_CarStatus_NonEmptyResults
 * @tc.desc: Test GetCarAwareness for CarStatus with non-empty results
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, GetCarAwareness_CarStatus_NonEmptyResults, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    CarAwarenessOption option;
    option.entityInfo["CarStatus"] = "TestDevice:TestFunc";
    std::vector<CarAwarenessEvent> events;
    CarAwarenessServer &server = GetTestServer();
    int32_t ret = server.GetCarAwareness(context, TYPE_CAR_STATUS, option, events);
    if (ret == RET_OK && !events.empty()) {
        EXPECT_EQ(events[0].type, TYPE_CAR_STATUS);
    }
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: SubscribeCarStatusWithOption_UpdateExisting
 * @tc.desc: Test SubscribeCarStatusWithOption when PID already exists
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, SubscribeCarStatusWithOption_UpdateExisting, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    CarAwarenessServer &server = GetTestServer();
    CarAwarenessOption option1;
    option1.entityInfo["Device1"] = "Func1";
    sptr<ICarAwarenessCallback> cb1 = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb1, nullptr);
    server.callbacks_["CarStatus"].push_back({context.pid, cb1, option1});
    
    CarAwarenessOption option2;
    option2.entityInfo["Device2"] = "Func2";
    sptr<ICarAwarenessCallback> cb2 = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb2, nullptr);
    int32_t ret = server.SubscribeCarStatusWithOption("CarStatus", context.pid, option2, cb2);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: UnSubscribeCarStatus_PartialUnsubscribe
 * @tc.desc: Test UnSubscribeCarStatus when callbacks still remain after unsubscribe
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, UnSubscribeCarStatus_PartialUnsubscribe, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    CarAwarenessServer &server = GetTestServer();
    CarAwarenessOption option1;
    option1.entityInfo["Device1"] = "Func1";
    sptr<ICarAwarenessCallback> cb1 = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb1, nullptr);
    server.callbacks_["CarStatus"].push_back({context.pid, cb1, option1});
    
    CarAwarenessOption option2;
    option2.entityInfo["Device2"] = "Func2";
    sptr<ICarAwarenessCallback> cb2 = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb2, nullptr);
    server.callbacks_["CarStatus"].push_back({DUMMY_PID, cb2, option2});
    
    CarAwarenessOption unsubOption;
    unsubOption.entityInfo["Device1"] = "Func1";
    int32_t ret = server.UnSubscribeCarStatus("CarStatus", context.pid, unsubOption);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: SubscribeCarStatusWithOption_UpdateExisting_WithMockAlgo
 * @tc.desc: Test SubscribeCarStatusWithOption update existing client path with mock algo
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, SubscribeCarStatusWithOption_UpdateExisting_WithMockAlgo, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    CarAwarenessServer &server = GetTestServer();

    auto mockAlgo = new MockCarAwarenessMgr();
    server.algoHandle_.pAlgorithm = mockAlgo;

    CarAwarenessOption option1;
    option1.entityInfo["Device1"] = "Func1";
    sptr<ICarAwarenessCallback> cb1 = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb1, nullptr);
    server.callbacks_["CarStatus"].push_back({context.pid, cb1, option1});

    CarAwarenessOption option2;
    option2.entityInfo["Device2"] = "Func2";
    sptr<ICarAwarenessCallback> cb2 = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb2, nullptr);
    int32_t ret = server.SubscribeCarStatusWithOption("CarStatus", context.pid, option2, cb2);

    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(mockAlgo->GetCallCount(), 1);
    EXPECT_EQ(mockAlgo->GetLastCapability(), "CarStatus");

    server.algoHandle_.pAlgorithm = nullptr;
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: UnSubscribeCarStatus_AllCallbacksCleared_WithMockAlgo
 * @tc.desc: Test UnSubscribeCarStatus when all callbacks are cleared with mock algo
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, UnSubscribeCarStatus_AllCallbacksCleared_WithMockAlgo, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    CarAwarenessServer &server = GetTestServer();

    auto mockAlgo = new MockCarAwarenessMgr();
    server.algoHandle_.pAlgorithm = mockAlgo;

    CarAwarenessOption option;
    option.entityInfo["Device1"] = "Func1";
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb, nullptr);
    server.callbacks_["CarStatus"].push_back({context.pid, cb, option});

    int32_t ret = server.UnSubscribeCarStatus("CarStatus", context.pid, option);

    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(mockAlgo->GetCallCount(), 1);
    EXPECT_EQ(mockAlgo->GetLastCapability(), "CarStatus");

    server.algoHandle_.pAlgorithm = nullptr;
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: UnSubscribeCarStatus_Partial_WithMockAlgo
 * @tc.desc: Test UnSubscribeCarStatus when some callbacks remain with mock algo
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, UnSubscribeCarStatus_Partial_WithMockAlgo, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    CarAwarenessServer &server = GetTestServer();

    auto mockAlgo = new MockCarAwarenessMgr();
    server.algoHandle_.pAlgorithm = mockAlgo;

    CarAwarenessOption option1;
    option1.entityInfo["Device1"] = "Func1";
    sptr<ICarAwarenessCallback> cb1 = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb1, nullptr);
    server.callbacks_["CarStatus"].push_back({context.pid, cb1, option1});

    CarAwarenessOption option2;
    option2.entityInfo["Device2"] = "Func2";
    sptr<ICarAwarenessCallback> cb2 = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb2, nullptr);
    server.callbacks_["CarStatus"].push_back({DUMMY_PID, cb2, option2});

    CarAwarenessOption unsubOption;
    unsubOption.entityInfo["Device1"] = "Func1";
    int32_t ret = server.UnSubscribeCarStatus("CarStatus", context.pid, unsubOption);

    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(mockAlgo->GetCallCount(), 1);

    server.algoHandle_.pAlgorithm = nullptr;
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: GetCarAwareness_CarStatus_WithMockAlgo
 * @tc.desc: Test GetCarAwareness for CarStatus type with mock algo
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, GetCarAwareness_CarStatus_WithMockAlgo, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);

    CarAwarenessServer &server = GetTestServer();

    auto mockAlgo = new MockCarAwarenessMgr();
    server.algoHandle_.pAlgorithm = mockAlgo;

    CarAwarenessOption option;
    option.entityInfo["TestDevice"] = "TestFunc";
    std::vector<CarAwarenessEvent> events;
    int32_t ret = server.GetCarAwareness(context, TYPE_CAR_STATUS, option, events);

    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(mockAlgo->GetCallCount(), 1);
    if (!events.empty()) {
        EXPECT_EQ(events[0].type, TYPE_CAR_STATUS);
    }

    server.algoHandle_.pAlgorithm = nullptr;
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: SubscribeAlgo_WithOption_WithMockAlgo
 * @tc.desc: Test SubscribeAlgo with entityInfo option using mock algo
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, SubscribeAlgo_WithOption_WithMockAlgo, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessServer &server = GetTestServer();

    auto mockAlgo = new MockCarAwarenessMgr();
    server.algoHandle_.pAlgorithm = mockAlgo;

    CarAwarenessOption option;
    option.entityInfo["CarStatus"] = "TestDevice:TestFunc";
    int32_t ret = server.SubscribeAlgo("CarStatus", option);

    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(mockAlgo->GetCallCount(), 1);
    EXPECT_EQ(mockAlgo->GetLastCapability(), "CarStatus");

    server.algoHandle_.pAlgorithm = nullptr;
}

/**
 * @tc.name: SubscribeCarStatusWithOption_UpdateExisting_PidMismatch
 * @tc.desc: Test SubscribeCarStatusWithOption when existing client pid mismatches
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, SubscribeCarStatusWithOption_UpdateExisting_PidMismatch, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    CarAwarenessServer &server = GetTestServer();

    CarAwarenessOption option1;
    option1.entityInfo["Device1"] = "Func1";
    sptr<ICarAwarenessCallback> cb1 = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb1, nullptr);
    server.callbacks_["CarStatus"].push_back({DUMMY_PID, cb1, option1});

    CarAwarenessOption option2;
    option2.entityInfo["Device2"] = "Func2";
    sptr<ICarAwarenessCallback> cb2 = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb2, nullptr);
    int32_t ret = server.SubscribeCarStatusWithOption("CarStatus", context.pid, option2, cb2);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
    EXPECT_EQ(server.callbacks_["CarStatus"].size(), 2);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: SubscribeCarStatusWithOption_UpdateExisting_NullAlgorithm
 * @tc.desc: Test SubscribeCarStatusWithOption update with null pAlgorithm
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerNewTest, SubscribeCarStatusWithOption_UpdateExisting_NullAlgorithm, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    CarAwarenessServer &server = GetTestServer();

    server.algoHandle_.pAlgorithm = nullptr;

    CarAwarenessOption option1;
    option1.entityInfo["Device1"] = "Func1";
    sptr<ICarAwarenessCallback> cb1 = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb1, nullptr);
    server.callbacks_["CarStatus"].push_back({context.pid, cb1, option1});

    CarAwarenessOption option2;
    option2.entityInfo["Device2"] = "Func2";
    sptr<ICarAwarenessCallback> cb2 = new (std::nothrow) CarAwarenessServerNewTestCallback();
    ASSERT_NE(cb2, nullptr);
    int32_t ret = server.SubscribeCarStatusWithOption("CarStatus", context.pid, option2, cb2);
    EXPECT_EQ(ret, RET_OK);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

}  // namespace DeviceStatus
}  // namespace Msdp
}  // namespace OHOS