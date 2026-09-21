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
#include "car_awareness_server_test.h"
#include "token_setproc.h"
#include "car_awareness_callback_proxy.h"

#undef LOG_TAG
#define LOG_TAG "CarAwarenessServerTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
using namespace Security::AccessToken;
namespace {
CarAwarenessServer carAwareness_;
uint64_t tokenId_ = 0;
const char *PERMISSION_SPATIALACTION = "ohos.permission.vehicle.MMA_SPATIALACTION";
const char *PERMISSION_WEATHER = "ohos.permission.vehicle.MMA_WEATHER";
const char *PERMISSION_ENERGYREFILL = "ohos.permission.vehicle.MMA_ENERGYREFILL";
std::mutex g_lockSetToken;
uint64_t g_shellTokenId = 0;
static constexpr int32_t DEFAULT_API_VERSION = 12;
static MockHapToken* g_mock = nullptr;
constexpr int32_t TYPE_SPATIAL_MOTION = 101;
constexpr int32_t TYPE_SPATIAL_POINT = 201;
constexpr int32_t TYPE_SPATIAL_GESTURE = 202;
constexpr int32_t TYPE_CAR_STATUS = 203;
constexpr int32_t TYPE_REALTIME_WEATHER = 102;
constexpr int32_t TYPE_REFULING = 103;
constexpr int32_t CAR_AWARENESS_SPECIFIC_ERR = 34000002;
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

    infoInstance.processName = "CarAwarenessServerTest";
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
    return tokenId;
}

void CarAwarenessServerTest::SetUp()
{}

void CarAwarenessServerTest::TearDown()
{
    carAwareness_.algoHandle_.pAlgorithm = nullptr;
}

void CarAwarenessServerTest::SetUpTestCase()
{
    g_shellTokenId = GetSelfTokenID();
    SetTestEvironment(g_shellTokenId);
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back(PERMISSION_SPATIALACTION);
    reqPerm.emplace_back(PERMISSION_WEATHER);
    reqPerm.emplace_back(PERMISSION_ENERGYREFILL);
    g_mock = new (std::nothrow) MockHapToken("CarAwarenessServerTest", reqPerm, true);
    CHKPV(g_mock);
    FI_HILOGI("SetUpTestCase ok.");
}

void CarAwarenessServerTest::TearDownTestCase()
{
    if (g_mock != nullptr) {
        delete g_mock;
        g_mock = nullptr;
    }
    std::lock_guard<std::mutex> lock(g_lockSetToken);
    g_shellTokenId = 0;
    SetSelfTokenID(g_shellTokenId);
}

void CarAwarenessServerTest::CarAwarenessServerTestCallback::OnAwarenessEvent(const CarAwarenessEvent &event)
{
    FI_HILOGI("OnAwarenessEvent type:%{public}d", event.type);
}

/**
 * @tc.name: CheckSystemCall001
 * @tc.desc: Test func named CheckSystemCall
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerTest, CheckSystemCall001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = Intention::UNKNOWN_INTENTION,
        .fullTokenId = (static_cast<uint64_t>(1) << 32),
        .tokenId = 0,
        .uid = 0,
        .pid = 0,
    };
    EXPECT_EQ(carAwareness_.CheckSystemCall(context), true);
    context.fullTokenId = 0;
    EXPECT_EQ(carAwareness_.CheckSystemCall(context), false);
}

/**
 * @tc.name: CheckSystemCall002
 * @tc.desc: Test func named CheckSystemCall with native token
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerTest, CheckSystemCall002, TestSize.Level0)
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
    EXPECT_EQ(carAwareness_.CheckSystemCall(context), true);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: SubscribeCapability001
 * @tc.desc: Test func named SubscribeCapability with null callback
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerTest, SubscribeCapability001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context;
    context.tokenId = tokenId_;
    CarAwarenessOption option;
    sptr<ICarAwarenessCallback> cb = nullptr;
    int32_t ret = carAwareness_.SubscribeCapability(context, TYPE_SPATIAL_MOTION, option, cb);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: SubscribeCapability002
 * @tc.desc: Test func named SubscribeCapability with system calling
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerTest, SubscribeCapability002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context {
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    EXPECT_EQ(carAwareness_.CheckSystemCall(context), true);
    CarAwarenessOption option;
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerTestCallback();
    ASSERT_NE(cb, nullptr);
    int32_t ret = carAwareness_.SubscribeCapability(context, TYPE_SPATIAL_POINT, option, cb);
    EXPECT_TRUE(ret >= RET_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: SubscribeCapability003
 * @tc.desc: Test func named SubscribeCapability with invalid type
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerTest, SubscribeCapability003, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context {
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    CarAwarenessOption option;
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerTestCallback();
    ASSERT_NE(cb, nullptr);
    int32_t ret = carAwareness_.SubscribeCapability(context, 999, option, cb);
    EXPECT_EQ(ret, CAR_AWARENESS_SPECIFIC_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: UnSubscribeCapability001
 * @tc.desc: Test func named UnSubscribeCapability
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerTest, UnSubscribeCapability001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context {
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    EXPECT_EQ(carAwareness_.CheckSystemCall(context), true);
    CarAwarenessOption option;
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerTestCallback();
    ASSERT_NE(cb, nullptr);
    int32_t ret = carAwareness_.UnSubscribeCapability(context, TYPE_SPATIAL_GESTURE, option, cb);
    EXPECT_EQ(ret, RET_OK);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: UnSubscribeCapability002
 * @tc.desc: Test func named UnSubscribeCapability with invalid type
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerTest, UnSubscribeCapability002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context {
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    CarAwarenessOption option;
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerTestCallback();
    ASSERT_NE(cb, nullptr);
    int32_t ret = carAwareness_.UnSubscribeCapability(context, 999, option, cb);
    EXPECT_EQ(ret, RET_OK);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: UpdateSpatialActionStatus001
 * @tc.desc: Test func named UpdateSpatialActionStatus
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerTest, UpdateSpatialActionStatus001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context {
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    EXPECT_EQ(carAwareness_.CheckSystemCall(context), true);
    int32_t ret = carAwareness_.UpdateSpatialActionStatus(context, 1);
    EXPECT_TRUE(ret >= RET_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: UpdateSpatialActionStatus002
 * @tc.desc: Test func named UpdateSpatialActionStatus with non-system calling
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerTest, UpdateSpatialActionStatus002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context;
    context.tokenId = tokenId_;
    context.fullTokenId = tokenId_;
    int32_t ret = carAwareness_.UpdateSpatialActionStatus(context, 1);
    EXPECT_EQ(ret, COMMON_NOT_SYSTEM_APP);
}

/**
 * @tc.name: UpdateSpatialActionZone001
 * @tc.desc: Test func named UpdateSpatialActionZone
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerTest, UpdateSpatialActionZone001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context {
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    EXPECT_EQ(carAwareness_.CheckSystemCall(context), true);
    int32_t ret = carAwareness_.UpdateSpatialActionZone(context, 1);
    EXPECT_TRUE(ret >= RET_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: UpdateSpatialActionZone002
 * @tc.desc: Test func named UpdateSpatialActionZone with non-system calling
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerTest, UpdateSpatialActionZone002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context;
    context.tokenId = tokenId_;
    context.fullTokenId = tokenId_;
    int32_t ret = carAwareness_.UpdateSpatialActionZone(context, 1);
    EXPECT_EQ(ret, COMMON_NOT_SYSTEM_APP);
}

/**
 * @tc.name: GetSupportCapabilityList001
 * @tc.desc: Test func named GetSupportCapabilityList
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerTest, GetSupportCapabilityList001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context;
    std::vector<std::string> capabilities;
    int32_t ret = carAwareness_.GetSupportCapabilityList(context, capabilities);
    EXPECT_TRUE(ret >= RET_ERR);
}

/**
 * @tc.name: GetCarAwareness001
 * @tc.desc: Test func named GetCarAwareness with system calling
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerTest, GetCarAwareness001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context {
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    EXPECT_EQ(carAwareness_.CheckSystemCall(context), true);
    CarAwarenessOption option;
    std::vector<CarAwarenessEvent> events;
    int32_t ret = carAwareness_.GetCarAwareness(context, TYPE_CAR_STATUS, option, events);
    EXPECT_TRUE(ret >= RET_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: GetCarAwareness002
 * @tc.desc: Test func named GetCarAwareness with non-system calling
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerTest, GetCarAwareness002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context;
    context.tokenId = tokenId_;
    context.fullTokenId = tokenId_;
    CarAwarenessOption option;
    std::vector<CarAwarenessEvent> events;
    int32_t ret = carAwareness_.GetCarAwareness(context, TYPE_CAR_STATUS, option, events);
    EXPECT_EQ(ret, COMMON_NOT_SYSTEM_APP);
}

/**
 * @tc.name: CheckSubPermissionByType001
 * @tc.desc: Test func named CheckSubPermissionByType with system API type
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerTest, CheckSubPermissionByType001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context {
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    int32_t ret = carAwareness_.CheckSubPermissionByType(context, TYPE_SPATIAL_POINT);
    EXPECT_EQ(ret, RET_OK);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: CheckSubPermissionByType002
 * @tc.desc: Test func named CheckSubPermissionByType with public API type but no permission
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerTest, CheckSubPermissionByType002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context;
    context.tokenId = tokenId_;
    context.fullTokenId = tokenId_;
    int32_t ret = carAwareness_.CheckSubPermissionByType(context, TYPE_SPATIAL_MOTION);
    EXPECT_EQ(ret, COMMON_PERMISSION_CHECK_ERROR);
}

/**
 * @tc.name: CheckSubPermissionByType0021
 * @tc.desc: Test func named CheckSubPermissionByType with public API type but no permission
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerTest, CheckSubPermissionByType0021, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context;
    context.tokenId = tokenId_;
    context.fullTokenId = tokenId_;
    int32_t ret = carAwareness_.CheckSubPermissionByType(context, TYPE_REALTIME_WEATHER);
    EXPECT_EQ(ret, COMMON_PERMISSION_CHECK_ERROR);
}

/**
 * @tc.name: CheckSubPermissionByType0021
 * @tc.desc: Test func named CheckSubPermissionByType with public API type but no permission
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerTest, CheckSubPermissionByType0022, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context;
    context.tokenId = tokenId_;
    context.fullTokenId = tokenId_;
    int32_t ret = carAwareness_.CheckSubPermissionByType(context, TYPE_REFULING);
    EXPECT_EQ(ret, COMMON_PERMISSION_CHECK_ERROR);
}


/**
 * @tc.name: CheckSubPermissionByType003
 * @tc.desc: Test func named CheckSubPermissionByType with unknown type
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerTest, CheckSubPermissionByType003, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context;
    context.tokenId = tokenId_;
    context.fullTokenId = tokenId_;
    int32_t ret = carAwareness_.CheckSubPermissionByType(context, 99);
    EXPECT_EQ(ret, CAR_AWARENESS_SPECIFIC_ERR);
}

/**
 * @tc.name: CheckSubPermissionByType004
 * @tc.desc: Test func named CheckSubPermissionByType with TYPE_REALTIME_WEATHER and system calling
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerTest, CheckSubPermissionByType004, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context {
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    int32_t ret = carAwareness_.CheckSubPermissionByType(context, TYPE_REALTIME_WEATHER);
    EXPECT_EQ(ret, RET_OK);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: CheckSubPermissionByType005
 * @tc.desc: Test func named CheckSubPermissionByType with TYPE_REFULING and system calling
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerTest, CheckSubPermissionByType005, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context {
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    int32_t ret = carAwareness_.CheckSubPermissionByType(context, TYPE_REFULING);
    EXPECT_EQ(ret, RET_OK);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: SubscribeCapability004
 * @tc.desc: Test func named SubscribeCapability with duplicate subscribe from same pid
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerTest, SubscribeCapability004, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context {
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    EXPECT_EQ(carAwareness_.CheckSystemCall(context), true);
    CarAwarenessOption option;
    sptr<ICarAwarenessCallback> cb1 = new (std::nothrow) CarAwarenessServerTestCallback();
    ASSERT_NE(cb1, nullptr);
    int32_t ret1 = carAwareness_.SubscribeCapability(context, TYPE_SPATIAL_POINT, option, cb1);
    EXPECT_TRUE(ret1 >= RET_ERR);
    sptr<ICarAwarenessCallback> cb2 = new (std::nothrow) CarAwarenessServerTestCallback();
    ASSERT_NE(cb2, nullptr);
    int32_t ret2 = carAwareness_.SubscribeCapability(context, TYPE_SPATIAL_POINT, option, cb2);
    EXPECT_TRUE(ret2 >= RET_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: UnSubscribeCapability003
 * @tc.desc: Test func named UnSubscribeCapability with TYPE_REALTIME_WEATHER
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerTest, UnSubscribeCapability003, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context {
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    CarAwarenessOption option;
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerTestCallback();
    ASSERT_NE(cb, nullptr);
    int32_t ret = carAwareness_.UnSubscribeCapability(context, TYPE_REALTIME_WEATHER, option, cb);
    EXPECT_EQ(ret, RET_OK);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: UnSubscribeCapability004
 * @tc.desc: Test func named UnSubscribeCapability with TYPE_REFULING
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerTest, UnSubscribeCapability004, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context {
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    EXPECT_EQ(flag, Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    CarAwarenessOption option;
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) CarAwarenessServerTestCallback();
    ASSERT_NE(cb, nullptr);
    int32_t ret = carAwareness_.UnSubscribeCapability(context, TYPE_REFULING, option, cb);
    EXPECT_EQ(ret, RET_OK);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: CarAwarenessCallbackProxyTest
 * @tc.desc: Test CarAwarenessCallbackProxy
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessServerTest, CarAwarenessCallbackProxyTest, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    sptr<IRemoteObject> remote;
    sptr<CarAwarenessCallbackProxy> proxy = new (std::nothrow) CarAwarenessCallbackProxy(remote);
    CarAwarenessEvent event;
    proxy->OnAwarenessEvent(event);
    EXPECT_TRUE(true);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
