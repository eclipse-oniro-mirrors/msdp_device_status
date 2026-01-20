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
constexpr int32_t RET_PARAM_ERR = 401;
constexpr int32_t RET_NO_SUPPORT = 801;
const char *PERMISSION_GET_PAGE_CONTENT = "ohos.permission.GET_SCREEN_CONTENT";
const char *PERMISSION_SEND_CONTROL_EVENT = "ohos.permission.SIMULATE_USER_INPUT";
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
 * @tc.name: IsParallelFeatureEnabled001
 * @tc.desc: Test func named IsParallelFeatureEnabled
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, IsParallelFeatureEnabled001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    int32_t windowId = 1;
    int32_t outStatus = 0;
    int32_t ret = onScreen_.IsParallelFeatureEnabled(context, windowId, outStatus);
    EXPECT_EQ(ret, RET_NO_SUPPORT);
}

/**
 * @tc.name: GetLiveStatus001
 * @tc.desc: Test func named GetLiveStatus
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, GetLiveStatus001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = onScreen_.GetLiveStatus();
    EXPECT_EQ(ret, RET_NO_SUPPORT);
}

/**
 * @tc.name: GetAppIdentifier001
 * @tc.desc: Test func named GetAppIdentifier
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, GetAppIdentifier001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string bundleName = "OnScreenServerTest";
    int32_t userId = 0;
    std::string appIdentifier = "";
    bool ret = onScreen_.GetAppIdentifier(bundleName, userId, appIdentifier);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: IsWhitelistAppCalling001
 * @tc.desc: Test func named IsWhitelistAppCalling
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, IsWhitelistAppCalling001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    bool ret =  onScreen_.IsWhitelistAppCalling(context);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: FillDumpCommonData001
 * @tc.desc: Test func named FillDumpCommonData
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, FillDumpCommonData001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    OnscreenAwarenessInfo info;
    onScreen_.FillDumpCommonData(info);
    EXPECT_EQ(info.bundleName, std::string("com.ohos.duoxi"));
}

/**
 * @tc.name: FillDumpScenarioTodo001
 * @tc.desc: Test func named FillDumpScenarioTodo
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, FillDumpData001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AwarenessCap cap;
    AwarenessOptions option;
    OnscreenAwarenessInfo wholeInfo = onScreen_.FillDumpData(cap, option);
    ASSERT_TRUE(wholeInfo.entityInfo.empty());
}

/**
 * @tc.name: FillDumpScenarioTodo002
 * @tc.desc: Test func named FillDumpScenarioTodo
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, FillDumpData002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AwarenessCap cap;
    cap.capList.push_back("contentUiTree");
    AwarenessOptions option;
    OnscreenAwarenessInfo wholeInfo = onScreen_.FillDumpData(cap, option);
    ASSERT_FALSE(wholeInfo.entityInfo.empty());
}

/**
 * @tc.name: FillDumpData003
 * @tc.desc: Test func named FillDumpData
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, FillDumpData003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AwarenessCap cap;
    cap.capList.push_back("contentUiTree");
    AwarenessOptions option;
    OnscreenAwarenessInfo wholeInfo = onScreen_.FillDumpData(cap, option);
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("uiTree") !=
                wholeInfo.entityInfo[0].entityInfo.end());
}

/**
 * @tc.name: FillDumpData004
 * @tc.desc: Test func named FillDumpContentUiTreeWithTree
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, FillDumpData004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AwarenessCap cap;
    cap.capList.push_back("contentUiTreeWithImage");
    AwarenessOptions option;
    OnscreenAwarenessInfo wholeInfo = onScreen_.FillDumpData(cap, option);
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("imagesCompID") !=
                wholeInfo.entityInfo[0].entityInfo.end());
}

/**
 * @tc.name: FillDumpData005
 * @tc.desc: Test func named FillDumpOcr
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, FillDumpData005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AwarenessCap cap;
    cap.capList.push_back("contentUiOcr");
    AwarenessOptions option;
    OnscreenAwarenessInfo wholeInfo = onScreen_.FillDumpData(cap, option);
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("uiTree") !=
                wholeInfo.entityInfo[0].entityInfo.end());
}

/**
 * @tc.name: FillDumpData006
 * @tc.desc: Test func named FillDumpData
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, FillDumpData006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AwarenessCap cap;
    cap.capList.push_back("contentScreenshot");
    AwarenessOptions option;
    OnscreenAwarenessInfo wholeInfo = onScreen_.FillDumpData(cap, option);
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("screenshotID") !=
                wholeInfo.entityInfo[0].entityInfo.end());
}

/**
 * @tc.name: FillDumpData007
 * @tc.desc: Test func named FillDumpData
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, FillDumpData007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AwarenessCap cap;
    cap.capList.push_back("contentLink");
    AwarenessOptions option;
    OnscreenAwarenessInfo wholeInfo = onScreen_.FillDumpData(cap, option);
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("pagLink") !=
                wholeInfo.entityInfo[0].entityInfo.end());
}

/**
 * @tc.name: FillDumpData008
 * @tc.desc: Test func named FillDumpData
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, FillDumpData008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AwarenessCap cap;
    cap.capList.push_back("interactionClick");
    AwarenessOptions option;
    OnscreenAwarenessInfo wholeInfo = onScreen_.FillDumpData(cap, option);
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("uiTree") !=
                wholeInfo.entityInfo[0].entityInfo.end());
}

/**
 * @tc.name: FillDumpData009
 * @tc.desc: Test func named FillDumpData
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, FillDumpData009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AwarenessCap cap;
    cap.capList.push_back("interactionScroll");
    AwarenessOptions option;
    OnscreenAwarenessInfo wholeInfo = onScreen_.FillDumpData(cap, option);
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("uiTree") !=
                wholeInfo.entityInfo[0].entityInfo.end());
}

/**
 * @tc.name: FillDumpData010
 * @tc.desc: Test func named FillDumpData
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, FillDumpData010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AwarenessCap cap;
    cap.capList.push_back("interactionTextSelection");
    AwarenessOptions option;
    OnscreenAwarenessInfo wholeInfo = onScreen_.FillDumpData(cap, option);
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("textSelection") !=
                wholeInfo.entityInfo[0].entityInfo.end());
}

/**
 * @tc.name: FillDumpData011
 * @tc.desc: Test func named FillDumpData
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, FillDumpData011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AwarenessCap cap;
    cap.capList.push_back("scenarioReading");
    AwarenessOptions option;
    OnscreenAwarenessInfo wholeInfo = onScreen_.FillDumpData(cap, option);
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("title") !=
                wholeInfo.entityInfo[0].entityInfo.end());
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("content") !=
                wholeInfo.entityInfo[0].entityInfo.end());
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("wordCount") !=
                wholeInfo.entityInfo[0].entityInfo.end());
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("lazyLoad") !=
                wholeInfo.entityInfo[0].entityInfo.end());
}

/**
 * @tc.name: FillDumpData012
 * @tc.desc: Test func named FillDumpData
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, FillDumpData012, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AwarenessCap cap;
    std::map<std::string, ValueObj> entityInfo;
    cap.capList.push_back("scenarioShortVideo");
    AwarenessOptions option;
    OnscreenAwarenessInfo wholeInfo = onScreen_.FillDumpData(cap, option);
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("category") !=
                wholeInfo.entityInfo[0].entityInfo.end());
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("hasBackGroundMusic") !=
                wholeInfo.entityInfo[0].entityInfo.end());
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("imagID") !=
                wholeInfo.entityInfo[0].entityInfo.end());
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("publisher") !=
                wholeInfo.entityInfo[0].entityInfo.end());
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("description") !=
                wholeInfo.entityInfo[0].entityInfo.end());
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("series") !=
                wholeInfo.entityInfo[0].entityInfo.end());
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("hotSearch") !=
                wholeInfo.entityInfo[0].entityInfo.end());
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("SearchTips") !=
                wholeInfo.entityInfo[0].entityInfo.end());
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("position") !=
                wholeInfo.entityInfo[0].entityInfo.end());
}

/**
 * @tc.name: FillDumpData013
 * @tc.desc: Test func named FillDumpData
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, FillDumpData013, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AwarenessCap cap;
    std::map<std::string, ValueObj> entityInfo;
    cap.capList.push_back("interactionTextSelection");
    AwarenessOptions option;
    OnscreenAwarenessInfo wholeInfo = onScreen_.FillDumpData(cap, option);
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("textSelection") !=
                wholeInfo.entityInfo[0].entityInfo.end());
}

/**
 * @tc.name: FillDumpData014
 * @tc.desc: Test func named FillDumpData
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, FillDumpData014, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AwarenessCap cap;
    std::map<std::string, ValueObj> entityInfo;
    cap.capList.push_back("scenarioTodo");
    AwarenessOptions option;
    OnscreenAwarenessInfo wholeInfo = onScreen_.FillDumpData(cap, option);
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("homeworkAssign") !=
                wholeInfo.entityInfo[0].entityInfo.end());
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("homeworkName") !=
                wholeInfo.entityInfo[0].entityInfo.end());
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("chatgroupName") !=
                wholeInfo.entityInfo[0].entityInfo.end());
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("pageName") !=
                wholeInfo.entityInfo[0].entityInfo.end());
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("subject") !=
                wholeInfo.entityInfo[0].entityInfo.end());
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("assigntime") !=
                wholeInfo.entityInfo[0].entityInfo.end());
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("deadline") !=
                wholeInfo.entityInfo[0].entityInfo.end());
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("description") !=
                wholeInfo.entityInfo[0].entityInfo.end());
    ASSERT_TRUE(wholeInfo.entityInfo[0].entityInfo.find("teacherName") !=
                wholeInfo.entityInfo[0].entityInfo.end());
}

/**
 * @tc.name: NotifyClient001
 * @tc.desc: Test func named NotifyClient
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, NotifyClient001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NO_FATAL_FAILURE(onScreen_.NotifyClient());
}

/**
 * @tc.name: OnScreenShotIntent001
 * @tc.desc: Test func named OnScreenShotIntent
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerTest, OnScreenShotIntent001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    AwarenessOptions option;
    OnscreenAwarenessInfo info;
    int32_t ret = onScreen_.OnScreenShotIntent(context, option, info);
    EXPECT_EQ(ret, RET_PARAM_ERR);

    option.entityInfo.insert(std::make_pair("windowId", 1));
    option.entityInfo.insert(std::make_pair("image", 1));
    ret = onScreen_.OnScreenShotIntent(context, option, info);
    EXPECT_EQ(ret, RET_PARAM_ERR);
}

} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS