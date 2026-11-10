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

#include <string>
#include <vector>

#include "devicestatus_define.h"
#include "fi_log.h"
#include "iremote_on_screen_callback.h"
#include "message_option.h"
#include "message_parcel.h"
#include "on_screen_callback_proxy.h"
#include "on_screen_callback_stub.h"

#undef LOG_TAG
#define LOG_TAG "OnScreenCallbackTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
using namespace testing::ext;

class TestOnScreenCallbackStub : public OnScreenCallbackStub {
public:
    void OnStateMgmtInfo(const std::vector<std::string>& results) override
    {
        receivedResults_ = results;
        called_ = true;
    }
    std::vector<std::string> receivedResults_;
    bool called_ = false;
};

class FailingOnScreenCallbackStub : public OnScreenCallbackStub {
public:
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) override
    {
        return E_DEVICESTATUS_GET_SERVICE_FAILED;
    }
};

class OnScreenCallbackTest : public testing::Test {
public:
    void SetUp() override
    {
        stub_ = sptr<TestOnScreenCallbackStub>::MakeSptr();
        ASSERT_NE(stub_, nullptr);
    }
    void TearDown() override {}
    sptr<TestOnScreenCallbackStub> stub_;
};

/**
 * @tc.name: OnScreenCallbackStub_OnStateMgmtInfoStub_001
 * @tc.desc: test for OnScreenCallbackTest
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenCallbackTest, OnScreenCallbackStub_OnStateMgmtInfoStub_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    ASSERT_TRUE(data.WriteInterfaceToken(OnScreenCallbackStub::GetDescriptor()));
    ASSERT_TRUE(data.WriteInt32(2));
    ASSERT_TRUE(data.WriteString("title1"));
    ASSERT_TRUE(data.WriteString("title2"));

    int32_t ret = stub_->OnRemoteRequest(
        static_cast<uint32_t>(IRemoteOnScreenCallback::ON_STATE_MGMT_INFO), data, reply, option);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_TRUE(stub_->called_);
    ASSERT_EQ(stub_->receivedResults_.size(), 2u);
    EXPECT_EQ(stub_->receivedResults_[0], "title1");
    EXPECT_EQ(stub_->receivedResults_[1], "title2");
}

/**
 * @tc.name: OnScreenCallbackStub_OnStateMgmtInfoStub_002
 * @tc.desc: test for OnScreenCallbackTest
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenCallbackTest, OnScreenCallbackStub_OnStateMgmtInfoStub_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    ASSERT_TRUE(data.WriteInterfaceToken(OnScreenCallbackStub::GetDescriptor()));

    int32_t ret = stub_->OnRemoteRequest(
        static_cast<uint32_t>(IRemoteOnScreenCallback::ON_STATE_MGMT_INFO), data, reply, option);
    EXPECT_EQ(ret, E_DEVICESTATUS_READ_PARCEL_ERROR);
    EXPECT_FALSE(stub_->called_);
}

/**
 * @tc.name: OnScreenCallbackStub_OnStateMgmtInfoStub_003
 * @tc.desc: test for OnScreenCallbackTest
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenCallbackTest, OnScreenCallbackStub_OnStateMgmtInfoStub_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    ASSERT_TRUE(data.WriteInterfaceToken(OnScreenCallbackStub::GetDescriptor()));
    ASSERT_TRUE(data.WriteInt32(1));

    int32_t ret = stub_->OnRemoteRequest(
        static_cast<uint32_t>(IRemoteOnScreenCallback::ON_STATE_MGMT_INFO), data, reply, option);
    EXPECT_EQ(ret, E_DEVICESTATUS_READ_PARCEL_ERROR);
    EXPECT_FALSE(stub_->called_);
}

/**
 * @tc.name: OnScreenCallbackProxy_OnStateMgmtInfo_001
 * @tc.desc: test for OnScreenCallbackTest
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenCallbackTest, OnScreenCallbackProxy_OnStateMgmtInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    sptr<OnScreenCallbackProxy> proxy = new (std::nothrow) OnScreenCallbackProxy(stub_->AsObject());
    ASSERT_NE(proxy, nullptr);
    std::vector<std::string> results = {"title1", "title2"};
    proxy->OnStateMgmtInfo(results);
    EXPECT_TRUE(stub_->called_);
    ASSERT_EQ(stub_->receivedResults_.size(), 2u);
    EXPECT_EQ(stub_->receivedResults_[0], "title1");
    EXPECT_EQ(stub_->receivedResults_[1], "title2");
}

/**
 * @tc.name: OnScreenCallbackProxy_OnStateMgmtInfo_002
 * @tc.desc: test for OnScreenCallbackTest
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenCallbackTest, OnScreenCallbackProxy_OnStateMgmtInfo_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    sptr<OnScreenCallbackProxy> proxy = new (std::nothrow) OnScreenCallbackProxy(nullptr);
    ASSERT_NE(proxy, nullptr);
    std::vector<std::string> results = {"title1"};
    proxy->OnStateMgmtInfo(results);
    EXPECT_FALSE(stub_->called_);
}

/**
 * @tc.name: OnScreenCallbackProxy_OnStateMgmtInfo_003
 * @tc.desc: test for OnScreenCallbackTest
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenCallbackTest, OnScreenCallbackProxy_OnStateMgmtInfo_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    sptr<FailingOnScreenCallbackStub> failingStub = sptr<FailingOnScreenCallbackStub>::MakeSptr();
    ASSERT_NE(failingStub, nullptr);
    sptr<OnScreenCallbackProxy> proxy = new (std::nothrow) OnScreenCallbackProxy(failingStub->AsObject());
    ASSERT_NE(proxy, nullptr);
    std::vector<std::string> results = {"title1"};
    proxy->OnStateMgmtInfo(results);
    EXPECT_FALSE(stub_->called_);
}

/**
 * @tc.name: OnScreenCallbackProxy_OnStateMgmtInfo_004
 * @tc.desc: test for OnScreenCallbackTest
 * @tc.type: FUNC
 */
HWTEST_F(OnScreenCallbackTest, OnScreenCallbackProxy_OnStateMgmtInfo_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    sptr<OnScreenCallbackProxy> proxy = new (std::nothrow) OnScreenCallbackProxy(stub_->AsObject());
    ASSERT_NE(proxy, nullptr);
    std::vector<std::string> results;
    proxy->OnStateMgmtInfo(results);
    EXPECT_TRUE(stub_->called_);
    EXPECT_TRUE(stub_->receivedResults_.empty());
}
}  // namespace OnScreen
}  // namespace DeviceStatus
}  // namespace Msdp
}  // namespace OHOS