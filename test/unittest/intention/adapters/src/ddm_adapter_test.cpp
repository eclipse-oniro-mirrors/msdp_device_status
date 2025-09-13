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

#include "accesstoken_kit.h"
#include <gtest/gtest.h>
#include "nativetoken_kit.h"
#include "token_setproc.h"

#include "ddm_adapter.h"
#include "ddm_adapter_impl.h"
#include "devicestatus_define.h"

#undef LOG_TAG
#define LOG_TAG "DDMAdapterTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
uint64_t g_tokenID { 0 };
const std::string SYSTEM_CORE { "system_core" };
const char* g_cores[] = { "ohos.permission.INPUT_MONITORING" };
} // namespace

class DDMAdapterTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase();
    static void SetPermission(const std::string &level, const char** perms, size_t permAmount);
    static void RemovePermission();
};

void DDMAdapterTest::SetPermission(const std::string &level, const char** perms, size_t permAmount)
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
        .processName = "DDMAdapterTest",
        .aplStr = level.c_str(),
    };
    g_tokenID = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(g_tokenID);
    OHOS::Security::AccessToken::AccessTokenKit::AccessTokenKit::ReloadNativeTokenInfo();
}

void DDMAdapterTest::RemovePermission()
{
    CALL_DEBUG_ENTER;
    int32_t ret = OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenID);
    if (ret != RET_OK) {
        FI_HILOGE("Failed to remove permission");
        return;
    }
}

void DDMAdapterTest::SetUpTestCase() {}

void DDMAdapterTest::SetUp() {}

void DDMAdapterTest::TearDown()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

/**
 * @tc.name: DDMAdapterTest
 * @tc.desc: Test Enable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DDMAdapterTest, TestEnable, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    DDMAdapter ddmAdapter;
    ASSERT_NO_FATAL_FAILURE(ddmAdapter.Enable());
    RemovePermission();
}

/**
 * @tc.name: DDMAdapterTest
 * @tc.desc: Test Disable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DDMAdapterTest, TestDisable, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    DDMAdapter ddmAdapter;
    ASSERT_NE(ddmAdapter.ddm_, nullptr);
    std::shared_ptr<DDMAdapterImpl> ddm = std::static_pointer_cast<DDMAdapterImpl>(ddmAdapter.ddm_);
    ddm->initCb_ = std::make_shared<DDMAdapterImpl::DmInitCb>();
    ddm->boardStateCb_ = std::make_shared<DDMAdapterImpl::DmBoardStateCb>(ddm);
    ASSERT_NO_FATAL_FAILURE(ddmAdapter.Disable());
    RemovePermission();
}

/**
 * @tc.name: DDMAdapterTest
 * @tc.desc: Test CheckSameAccountToLocal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DDMAdapterTest, TestCheckSameAccountToLocal, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    DDMAdapter ddmAdapter;
    ASSERT_NO_FATAL_FAILURE(ddmAdapter.CheckSameAccountToLocal(""));
    RemovePermission();
}

/**
 * @tc.name: DDMAdapterTest
 * @tc.desc: Test OnBoardOnline
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DDMAdapterTest, TestOnBoardOnline, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    DDMAdapterImpl ddmAdapterImpl;
    ASSERT_NO_FATAL_FAILURE(ddmAdapterImpl.OnBoardOnline(""));
    RemovePermission();
}

/**
 * @tc.name: DDMAdapterTest
 * @tc.desc: Test OnBoardOffline
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DDMAdapterTest, TestOnBoardOffline, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    DDMAdapterImpl ddmAdapterImpl;
    ASSERT_NO_FATAL_FAILURE(ddmAdapterImpl.OnBoardOffline(""));
    RemovePermission();
}

/**
 * @tc.name: DDMAdapterTest
 * @tc.desc: Test CheckSameAccountToLocalWithUid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DDMAdapterTest, TestCheckSameAccountToLocalWithUid, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    DDMAdapterImpl ddmAdapterImpl;
    std::string networkId = {"softbus"};
    int32_t uid = 0;
    bool ret = ddmAdapterImpl.CheckSameAccountToLocalWithUid(networkId, uid);
    ASSERT_FALSE(ret);
    RemovePermission();
}

/**
 * @tc.name: DDMAdapterTest
 * @tc.desc: Test CheckSinkIsSameAccount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DDMAdapterTest, TestCheckSinkIsSameAccount, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    DDMAdapterImpl ddmAdapterImpl;
    std::string srcNetworkId = {"softbus"};
    int32_t srcUserId = 0;
    std::string srcAccountId = {"softbus"};
    bool ret = ddmAdapterImpl.CheckSinkIsSameAccount(srcNetworkId, srcUserId, srcAccountId);
    ASSERT_FALSE(ret);
    RemovePermission();
}

/**
 * @tc.name: DDMAdapterTest
 * @tc.desc: Test GetDmAccessCalleeSink
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DDMAdapterTest, TestGetDmAccessCalleeSink, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    DDMAdapterImpl ddmAdapterImpl;
    DistributedHardware::DmAccessCallee callee;

    bool ret = ddmAdapterImpl.GetDmAccessCalleeSink(callee);
    ASSERT_FALSE(ret);
    RemovePermission();
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS