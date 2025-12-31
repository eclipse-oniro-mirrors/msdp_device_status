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
#include "on_screen_server_new_test.h"
#include "token_setproc.h"
 
#undef LOG_TAG
#define LOG_TAG "OnScreenServerNewTest"
 
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
using namespace testing::ext;
using namespace Security::AccessToken;
namespace {
const char *PERMISSION_GET_PAGE_CONTENT = "ohos.permission.GET_SCREEN_CONTENT";
const char *PERMISSION_SEND_CONTROL_EVENT = "ohos.permission.SIMULATE_USER_INPUT";
std::mutex g_lockSetToken;
uint64_t g_shellTokenId = 0;
static constexpr int32_t DEFAULT_API_VERSION = 12;
static MockHapToken *g_mock = nullptr;
uint64_t tokenId_ = 0;
}  // namespace
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
    EXPECT_EQ(0, SetSelfTokenID(GetShellTokenId()));  // set shell token
 
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
 
void OnScreenServerNewTest::SetUp()
{}
 
void OnScreenServerNewTest::TearDown()
{}
 
void OnScreenServerNewTest::SetUpTestCase()
{
    g_shellTokenId = GetSelfTokenID();
    SetTestEvironment(g_shellTokenId);
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back(PERMISSION_GET_PAGE_CONTENT);
    reqPerm.emplace_back(PERMISSION_SEND_CONTROL_EVENT);
    g_mock = new (std::nothrow) MockHapToken("OnScreenServerNewTest", reqPerm, true);
    CHKPV(g_mock);
    FI_HILOGI("SetUpTestCase ok.");
}
 
void OnScreenServerNewTest::TearDownTestCase()
{
    if (g_mock != nullptr) {
        delete g_mock;
        g_mock = nullptr;
    }
    std::lock_guard<std::mutex> lock(g_lockSetToken);
    g_shellTokenId = 0;
    SetSelfTokenID(g_shellTokenId);
}
 
void OnScreenServerNewTest::OnScreenServerNewTestCallback::OnScreenChange(const std::string &changeInfo)
{
    FI_HILOGI("OnScreenChange");
}
 
/**
 * @tc.name: RegisterAwarenessCallback
 * @tc.desc: Test func named RegisterAwarenessCallback
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerNewTest, RegisterAwarenessCallback, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    OnScreenServer onScreen;
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    sptr<IRemoteOnScreenCallback> callback = new (std::nothrow) OnScreenServerNewTestCallback();
    AwarenessCap cap;
    AwarenessOptions option;
    int32_t ret = onScreen.RegisterAwarenessCallback(context, cap, callback, option);
    EXPECT_NE(ret, RET_OK);
 
    context.tokenId = 1;
    ret = onScreen.RegisterAwarenessCallback(context, cap, callback, option);
    EXPECT_NE(ret, RET_OK);
}
 
/**
 * @tc.name: UnregisterAwarenessCallback
 * @tc.desc: Test func named UnregisterAwarenessCallback
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerNewTest, UnregisterAwarenessCallback, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    OnScreenServer onScreen;
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    AwarenessCap cap;
    sptr<IRemoteOnScreenCallback> callback = new (std::nothrow) OnScreenServerNewTestCallback();
    int32_t ret = onScreen.UnregisterAwarenessCallback(context, cap, callback);
    EXPECT_NE(ret, RET_OK);
 
    context.tokenId = 1;
    ret = onScreen.UnregisterAwarenessCallback(context, cap, callback);
    EXPECT_NE(ret, RET_OK);
}
 
/**
 * @tc.name: Trigger
 * @tc.desc: Test func named Trigger
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerNewTest, Trigger, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    OnScreenServer onScreen;
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    AwarenessCap cap;
    AwarenessOptions option;
    OnscreenAwarenessInfo info;
    int32_t ret = onScreen.Trigger(context, cap, option, info);
    EXPECT_NE(ret, RET_OK);
 
    context.tokenId = 1;
    ret = onScreen.Trigger(context, cap, option, info);
    EXPECT_NE(ret, RET_OK);
}
 
/**
 * @tc.name: FillDumpData
 * @tc.desc: Test func named FillDumpData
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerNewTest, FillDumpData, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    OnScreenServer onScreen;
    AwarenessCap cap;
    AwarenessOptions option;
    sptr<IRemoteOnScreenCallback> callback = new (std::nothrow) OnScreenServerNewTestCallback();
    OnscreenAwarenessInfo info = onScreen.FillDumpData(cap, option);
    EXPECT_TRUE(info.entityInfo.empty());
    
    cap.capList.emplace_back("Marshalling test");
    cap.capList.emplace_back("contentUiTree");
    cap.capList.emplace_back("contentUiOcr");
    cap.capList.emplace_back("contentScreenshot");
    cap.capList.emplace_back("contentLink");
    cap.capList.emplace_back("contentUiTreeWithImage");
    cap.capList.emplace_back("interactionTextSelection");
    cap.capList.emplace_back("interactionClick");
    cap.capList.emplace_back("interactionScroll");
    cap.capList.emplace_back("scenarioReading");
    cap.capList.emplace_back("scenarioShortVideo");
    cap.capList.emplace_back("scenarioActivity");
    cap.capList.emplace_back("scenarioTodo");
    info = onScreen.FillDumpData(cap, option);
    callback->OnScreenAwareness(info);
    EXPECT_FALSE(info.entityInfo.empty());
}
 
/**
 * @tc.name: IsWhitelistAppCalling
 * @tc.desc: Test func named IsWhitelistAppCalling
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerNewTest, IsWhitelistAppCalling, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    OnScreenServer onScreen;
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    bool ret = onScreen.IsWhitelistAppCalling(context);
    EXPECT_FALSE(ret);
}
 
/**
 * @tc.name: SaveCallbackInfo
 * @tc.desc: Test func named SaveCallbackInfo
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerNewTest, SaveCallbackInfo, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    OnScreenServer onScreen;
    AwarenessCap cap;
    cap.capList.emplace_back("contentUiTree");
    sptr<IRemoteOnScreenCallback> callback = new (std::nothrow) OnScreenServerNewTestCallback();
    bool ret = onScreen.SaveCallbackInfo(callback, cap);
    EXPECT_TRUE(ret);
 
    ret = onScreen.SaveCallbackInfo(callback, cap);
    EXPECT_TRUE(ret);
}
 
/**
 * @tc.name: RemoveCallbackInfo
 * @tc.desc: Test func named RemoveCallbackInfo
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerNewTest, RemoveCallbackInfo, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    OnScreenServer onScreen;
    AwarenessCap cap;
    sptr<IRemoteOnScreenCallback> callbackTest1 = new (std::nothrow) OnScreenServerNewTestCallback();
    std::set<std::string> sets;
    sets.insert("contentUiTree");
    onScreen.callbackInfo_.emplace(callbackTest1, sets);
    sptr<IRemoteOnScreenCallback> callbackTest2 = new (std::nothrow) OnScreenServerNewTestCallback();
    bool ret = onScreen.RemoveCallbackInfo(callbackTest2, cap);
    EXPECT_TRUE(ret);
 
    cap.capList.emplace_back("contentUiTree");
    ret = onScreen.RemoveCallbackInfo(callbackTest1, cap);
    EXPECT_TRUE(ret);
}
 
/**
 * @tc.name: GetUnusedCap
 * @tc.desc: Test func named GetUnusedCap
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerNewTest, GetUnusedCap, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    OnScreenServer onScreen;
    AwarenessCap cap;
    sptr<IRemoteOnScreenCallback> callbackTest = new (std::nothrow) OnScreenServerNewTestCallback();
    std::set<std::string> sets;
    sets.insert("contentUiTree");
    onScreen.callbackInfo_.emplace(callbackTest, sets);
    cap.capList.emplace_back("scenarioActivity");
    auto ret = onScreen.GetUnusedCap(cap);
    EXPECT_EQ(ret.size(), 1);
}

/**
 * @tc.name: IsSystemCalling
 * @tc.desc: Test func named IsSystemCalling
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerNewTest, IsSystemCalling, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    OnScreenServer onScreen;
    bool ret = onScreen.IsSystemCalling(context);
    ASSERT_TRUE(ret);

    context.fullTokenId = tokenId_;
    ret = onScreen.IsSystemCalling(context);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: RegisterAwarenessCallback
 * @tc.desc: Test func named RegisterAwarenessCallback001
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerNewTest, RegisterAwarenessCallback001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    OnScreenServer onScreen;
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    sptr<IRemoteOnScreenCallback> callback = new (std::nothrow) OnScreenServerNewTestCallback();
    AwarenessCap cap;
    cap.capList = std::vector<std::vector>{ "aaa", "bbb" };
    AwarenessOptions option;
    int32_t ret = onScreen.RegisterAwarenessCallback(context, cap, callback, option);
    EXPECT_NE(ret, RET_ERR);
}

/**
 * @tc.name: RegisterAwarenessCallback
 * @tc.desc: Test func named RegisterAwarenessCallback002
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerNewTest, RegisterAwarenessCallback002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    OnScreenServer onScreen;
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    sptr<IRemoteOnScreenCallback> callback = new (std::nothrow) OnScreenServerNewTestCallback();
    AwarenessCap cap;
    cap.capList = std::vector<std::vector>{ "ccc", "scenarioTodo" };
    AwarenessOptions option;
    int32_t ret = onScreen.RegisterAwarenessCallback(context, cap, callback, option);
    EXPECT_NE(ret, RET_ERR);
}

/**
 * @tc.name: RegisterAwarenessCallback
 * @tc.desc: Test func named RegisterAwarenessCallback003
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenServerNewTest, RegisterAwarenessCallback003, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    OnScreenServer onScreen;
    CallingContext context{
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    sptr<IRemoteOnScreenCallback> callback = new (std::nothrow) OnScreenServerNewTestCallback();
    AwarenessCap cap;
    cap.capList = std::vector<std::vector>{ "scenarioActivity", "scenarioShortVideo", "abc" };
    AwarenessOptions option;
    int32_t ret = onScreen.RegisterAwarenessCallback(context, cap, callback, option);
    EXPECT_NE(ret, RET_ERR);
}
}  // namespace OnScreen
}  // namespace DeviceStatus
}  // namespace Msdp
}  // namespace OHOS