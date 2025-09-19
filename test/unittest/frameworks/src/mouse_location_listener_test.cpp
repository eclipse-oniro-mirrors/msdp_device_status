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

#include <vector>

#include <unistd.h>

#include "accesstoken_kit.h"
#include "device_manager.h"
#include "dm_device_info.h"
#include <gtest/gtest.h>
#include "nativetoken_kit.h"
#include "pointer_event.h"
#include "securec.h"
#include "token_setproc.h"

#include "devicestatus_define.h"
#include "devicestatus_errors.h"
#include "i_event_listener.h"
#include "interaction_manager.h"
#include "mouse_location_listener_test.h"
#include "utility.h"

#undef LOG_TAG
#define LOG_TAG "MouseLocationListenerTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
const std::string COOPERATE_ACCESS_PERMISSION { "ohos.permission.COOPERATE_MANAGER" };
const std::string DM_SERVICE_ACCESS_PERMISSION { "ohos.permission.ACCESS_SERVICE_DM" };
const std::string DM_SERVICE_ACCESS_NEWPERMISSION { "ohos.permission.DISTRIBUTED_DATASYNC" };
const std::string PKG_NAME_PREFIX { "DBinderBus_Dms_" };
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
std::mutex g_lockSetToken;
uint64_t g_shellTokenId = 0;
static constexpr int32_t DEFAULT_API_VERSION = 12;
static MockHapToken* g_mock = nullptr;
#define DSTB_HARDWARE DistributedHardware::DeviceManager::GetInstance()
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

uint64_t GetNativeTokenIdFromProcess(const std::string &process)
{
    uint64_t selfTokenId = GetSelfTokenID();
    uint64_t getShellTokenId = GetShellTokenId();
    FI_HILOGI("selfTokenId:%{public}" PRId64 ", getShellTokenId:%{public}" PRId64, selfTokenId, getShellTokenId);
    EXPECT_EQ(0, SetSelfTokenID(GetShellTokenId()));

    std::string dumpInfo;
    Security::AccessToken::AtmToolsParamInfo info;
    info.processName = process;
    Security::AccessToken::AccessTokenKit::DumpTokenInfo(info, dumpInfo);
    size_t pos = dumpInfo.find("\"tokenID\": ");
    if (pos == std::string::npos) {
        FI_HILOGE("tokenID not find");
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
    Security::AccessToken::AccessTokenID tokenID;
    iss >> tokenID;
    return tokenID;
}

int32_t AllocTestHapToken(const Security::AccessToken::HapInfoParams& hapInfo,
    Security::AccessToken::HapPolicyParams& hapPolicy, Security::AccessToken::AccessTokenIDEx& tokenIdEx)
{
    uint64_t selfTokenId = GetSelfTokenID();
    for (auto& permissionStateFull : hapPolicy.permStateList) {
        Security::AccessToken::PermissionDef permDefResult;
        if (Security::AccessToken::AccessTokenKit::GetDefPermission(permissionStateFull.permissionName, permDefResult)
            != Security::AccessToken::RET_SUCCESS) {
            continue;
        }
        if (permDefResult.availableLevel > hapPolicy.apl) {
            hapPolicy.aclRequestedList.emplace_back(permissionStateFull.permissionName);
        }
    }
    if (GetNativeTokenIdFromProcess("foundation") == selfTokenId) {
        return Security::AccessToken::AccessTokenKit::InitHapToken(hapInfo, hapPolicy, tokenIdEx);
    }

    MockNativeToken mock("foundation");
    int32_t ret = Security::AccessToken::AccessTokenKit::InitHapToken(hapInfo, hapPolicy, tokenIdEx);

    EXPECT_EQ(0, SetSelfTokenID(selfTokenId));

    return ret;
}

int32_t DeleteTestHapToken(Security::AccessToken::AccessTokenID tokenID)
{
    uint64_t selfTokenId = GetSelfTokenID();
    if (GetNativeTokenIdFromProcess("foundation") == selfTokenId) {
        return Security::AccessToken::AccessTokenKit::DeleteToken(tokenID);
    }
    MockNativeToken mock("foundation");
    int32_t ret = Security::AccessToken::AccessTokenKit::DeleteToken(tokenID);
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId));
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
    Security::AccessToken::HapInfoParams infoParams = {
        .userID = 0,
        .bundleName = bundle,
        .instIndex = 0,
        .appIDDesc = "AccessTokenTestAppID",
        .apiVersion = DEFAULT_API_VERSION,
        .isSystemApp = isSystemApp,
        .appDistributionType = "",
    };

    Security::AccessToken::HapPolicyParams policyParams = {
        .apl = Security::AccessToken::APL_NORMAL,
        .domain = "accesstoken_test_domain",
    };
    for (size_t i = 0; i < reqPerm.size(); ++i) {
        Security::AccessToken::PermissionDef permDefResult;
        if (Security::AccessToken::AccessTokenKit::GetDefPermission(reqPerm[i], permDefResult)
            != Security::AccessToken::RET_SUCCESS) {
            continue;
        }
        Security::AccessToken::PermissionStateFull permState = {
            .permissionName = reqPerm[i],
            .isGeneral = true,
            .resDeviceID = {"local3"},
            .grantStatus = {Security::AccessToken::PermissionState::PERMISSION_DENIED},
            .grantFlags = {Security::AccessToken::PermissionFlag::PERMISSION_DEFAULT_FLAG}
        };
        policyParams.permStateList.emplace_back(permState);
        if (permDefResult.availableLevel > policyParams.apl) {
            policyParams.aclRequestedList.emplace_back(reqPerm[i]);
        }
    }

    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    EXPECT_EQ(Security::AccessToken::RET_SUCCESS, AllocTestHapToken(infoParams, policyParams, tokenIdEx));
    mockToken_= tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_NE(mockToken_, Security::AccessToken::INVALID_TOKENID);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));
}

MockHapToken::~MockHapToken()
{
    if (mockToken_ != Security::AccessToken::INVALID_TOKENID) {
        EXPECT_EQ(0, DeleteTestHapToken(mockToken_));
    }
    EXPECT_EQ(0, SetSelfTokenID(selfToken_));
}

void MouseLocationListenerTest::SetUpTestCase()
{
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back(COOPERATE_ACCESS_PERMISSION);
    reqPerm.emplace_back(DM_SERVICE_ACCESS_PERMISSION);
    reqPerm.emplace_back(DM_SERVICE_ACCESS_NEWPERMISSION);
    g_mock = new (std::nothrow) MockHapToken("MouseLocationListenerTest", reqPerm, true);
    if (g_mock != nullptr) {
        delete g_mock;
        g_mock = nullptr;
    };
    FI_HILOGI("SetUpTestCase ok.");
}

void MouseLocationListenerTest::SetUp() {}

void MouseLocationListenerTest::TearDown()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

std::string MouseLocationListenerTest::GetLocalNetworkId()
{
    auto packageName = PKG_NAME_PREFIX + std::to_string(getpid());
    OHOS::DistributedHardware::DmDeviceInfo dmDeviceInfo;
    if (int32_t errCode = DSTB_HARDWARE.GetLocalDeviceInfo(packageName, dmDeviceInfo); errCode != RET_OK) {
        FI_HILOGE("GetLocalBasicInfo failed, errCode:%{public}d", errCode);
        return {};
    }
    FI_HILOGD("LocalNetworkId:%{public}s", Utility::Anonymize(dmDeviceInfo.networkId).c_str());
    return dmDeviceInfo.networkId;
}

class EventListener : public IEventListener {
    void OnMouseLocationEvent(const std::string &networkId, const Event &event) override;
};

void EventListener::OnMouseLocationEvent(const std::string &networkId, const Event &event)
{
    FI_HILOGI("NetworkId:%{public}s, DisplayX:%{public}d, displayY:%{public}d,"
        "displayWidth:%{public}d, displayHeight:%{public}d", Utility::Anonymize(networkId).c_str(),
        event.displayX, event.displayY, event.displayWidth, event.displayHeight);
}

/**
 * @tc.name: RegisterEventListener_00
 * @tc.desc: Default NetworkId, Valid Listener.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseLocationListenerTest, RegisterEventListener_00, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string networkId { "Default" };
    auto listener = std::make_shared<EventListener>();
    int32_t ret = InteractionManager::GetInstance()->RegisterEventListener(networkId, listener);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    ASSERT_EQ(ret, RET_OK);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

/**
 * @tc.name: RegisterEventListener_01
 * @tc.desc: Default NetworkId, NULL Listener.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseLocationListenerTest, RegisterEventListener_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string networkId { "Default" };
    int32_t ret = InteractionManager::GetInstance()->RegisterEventListener(networkId, nullptr);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    ASSERT_EQ(ret, COMMON_PARAMETER_ERROR);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

/**
 * @tc.name: UnregisterEventListener_00
 * @tc.desc: Local NetworkId, Valid Listener.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseLocationListenerTest, UnregisterEventListener_00, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string networkId { "Default" };
    auto listener = std::make_shared<EventListener>();
    int32_t ret = InteractionManager::GetInstance()->RegisterEventListener(networkId, listener);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    ASSERT_EQ(ret, RET_OK);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COORDINATION
    ret = InteractionManager::GetInstance()->UnregisterEventListener(networkId, listener);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    ASSERT_EQ(ret, RET_OK);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

/**
 * @tc.name: UnregisterEventListener_01
 * @tc.desc: Local networkId, NULL Listener.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseLocationListenerTest, UnregisterEventListener_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string networkId { "Default" };
    auto listener = std::make_shared<EventListener>();
    int32_t ret = InteractionManager::GetInstance()->RegisterEventListener(networkId, listener);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    ASSERT_EQ(ret, RET_OK);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COORDINATION
    ret = InteractionManager::GetInstance()->UnregisterEventListener(networkId, nullptr);
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    ASSERT_EQ(ret, RET_OK);
#else
    ASSERT_EQ(ret, ERROR_UNSUPPORT);
#endif // OHOS_BUILD_ENABLE_COORDINATION
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS

