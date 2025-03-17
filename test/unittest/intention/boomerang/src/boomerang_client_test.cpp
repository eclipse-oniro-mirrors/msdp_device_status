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
 
#include <future>
#include <optional>
 
#include <unistd.h>
#include <utility>
 
#include <gtest/gtest.h>
#include <gmock/gmock.h>
 
#include "boomerang_callback_stub.h"
#include "boomerang_client_test_mock.h"
#include "boomerang_client.h"
#include "boomerang_callback.h"
#include "boomerang_params.h"
#include "default_params.h"
#include "devicestatus_define.h"
#include "devicestatus_errors.h"
#include "i_hotarea_listener.h"
#include "i_event_listener.h"
#include "tunnel_client.h"
 
#undef LOG_TAG
#define LOG_TAG "BoomerangClientTest"
 
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
using namespace testing;
namespace {
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
inline constexpr size_t MAX_STRING_LEN{1024};
// const std::string SYSTEM_BASIC { "system_basic" };
} // namespace
 
class BoomerangClientTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase();
    static void TearDownTestCase();
    class BoomerangClientTestCallback : public BoomerangCallbackStub {
    public:
    void OnScreenshotResult(const BoomerangData& data);
    private:
    BoomerangData data_;
    };
};
 
void BoomerangClientTest::SetUpTestCase() {}
 
void BoomerangClientTest::TearDownTestCase() {}
 
void BoomerangClientTest::SetUp() {}
 
void BoomerangClientTest::TearDown()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}
void BoomerangClientTest::BoomerangClientTestCallback::OnScreenshotResult(const BoomerangData& data)
{
    GTEST_LOG_(INFO) << "BoomerangClientTestCallback type: " << data.type;
    GTEST_LOG_(INFO) << "BoomerangClientTestCallback status: " << data.status;
    EXPECT_TRUE(data.type == BoomerangType::BOOMERANG_TYPE_BOOMERANG &&
        data.status == BoomerangStatus::BOOMERANG_STATUS_NOT_SCREEN_SHOT)
        << "BoomerangClientTestCallback failed";
}
 
class CoordinationListenerTest : public ICoordinationListener {
public:
        CoordinationListenerTest() : ICoordinationListener() {}
        void OnCoordinationMessage(const std::string &networkId, CoordinationMessage msg) override
        {
            FI_HILOGD("Register coordination listener test");
            (void) networkId;
        };
    };
 
class TestEventListener final : public IEventListener {
public:
    TestEventListener() : IEventListener() {};
    ~TestEventListener() = default;
 
    void OnMouseLocationEvent(const std::string &networkId, const Event &event) override
    {
        (void) networkId;
        (void) event;
    };
};
 
/**
 * @tc.name: BoomerangClientTest_001
 * @tc.desc: BoomerangClientTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangClientTest, BoomerangClientTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    sptr<IRemoteBoomerangCallback> callback = new (std::nothrow) BoomerangClientTestCallback();
    std::shared_ptr<CoordinationListenerTest> consumer =
        std::make_shared<CoordinationListenerTest>();
    char bundleName[MAX_STRING_LEN] = {0};
    TunnelClient tunnel;
    BoomerangClient boomerangClient;
    NiceMock<BoomerangClientMock> boomerangClientMock;
    EXPECT_CALL(boomerangClientMock, AddWatch).WillOnce(Return(RET_OK));
    int32_t ret = boomerangClient.SubscribeCallback(
        tunnel, BoomerangType::BOOMERANG_TYPE_BOOMERANG, bundleName, callback);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_CALL(boomerangClientMock, RemoveWatch).WillRepeatedly(Return(RET_OK));
    ret = boomerangClient.UnsubscribeCallback(tunnel, BoomerangType::BOOMERANG_TYPE_BOOMERANG, bundleName, callback);
    ASSERT_EQ(ret, RET_OK);
}
 
/**
 * @tc.name: BoomerangClientTest_002
 * @tc.desc: BoomerangClientTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangClientTest, BoomerangClientTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    sptr<IRemoteBoomerangCallback> callback = new (std::nothrow) BoomerangClientTestCallback();
    std::shared_ptr<CoordinationListenerTest> consumer =
        std::make_shared<CoordinationListenerTest>();
    char bundleName[MAX_STRING_LEN] = {0};
    TunnelClient tunnel;
    BoomerangClient boomerangClient;
    NiceMock<BoomerangClientMock> boomerangClientMock;
    EXPECT_CALL(boomerangClientMock, AddWatch).WillOnce(Return(RET_OK));
    int32_t ret = boomerangClient.NotifyMetadataBindingEvent(tunnel, bundleName, callback);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_CALL(boomerangClientMock, RemoveWatch).WillRepeatedly(Return(RET_OK));
}
 
/**
 * @tc.name: BoomerangClientTest_003
 * @tc.desc: BoomerangClientTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangClientTest, BoomerangClientTest_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TunnelClient tunnel;
    std::string metadata;
    BoomerangClient boomerangClient;
    NiceMock<BoomerangClientMock> boomerangClientMock;
    sptr<IRemoteBoomerangCallback> callback = new (std::nothrow) BoomerangClientTestCallback();
    char bundleName[MAX_STRING_LEN] = {0};
    EXPECT_CALL(boomerangClientMock, AddWatch).WillOnce(Return(RET_OK));
    int32_t ret = boomerangClient.SubscribeCallback(
        tunnel, BoomerangType::BOOMERANG_TYPE_BOOMERANG, bundleName, callback);
    ASSERT_EQ(ret, RET_OK);
    ret = boomerangClient.SubmitMetadata(tunnel, metadata);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_CALL(boomerangClientMock, RemoveWatch).WillRepeatedly(Return(RET_OK));
}
 
/**
 * @tc.name: BoomerangClientTest_004
 * @tc.desc: BoomerangClientTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangClientTest, BoomerangClientTest_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TunnelClient tunnel;
    std::string metadata;
    BoomerangClient boomerangClient;
    NiceMock<BoomerangClientMock> boomerangClientMock;
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = std::shared_ptr<Media::PixelMap>();
    sptr<IRemoteBoomerangCallback> callback = new (std::nothrow) BoomerangClientTestCallback();
    EXPECT_CALL(boomerangClientMock, AddWatch).WillOnce(Return(RET_OK));
    int32_t ret = boomerangClient.BoomerangEncodeImage(tunnel, pixelMap, metadata, callback);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_CALL(boomerangClientMock, RemoveWatch).WillRepeatedly(Return(RET_OK));
}
 
/**
 * @tc.name: BoomerangClientTest_005
 * @tc.desc: BoomerangClientTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangClientTest, BoomerangClientTest_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TunnelClient tunnel;
    std::string metadata;
    BoomerangClient boomerangClient;
    NiceMock<BoomerangClientMock> boomerangClientMock;
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = std::shared_ptr<Media::PixelMap>();
    sptr<IRemoteBoomerangCallback> callback = new (std::nothrow) BoomerangClientTestCallback();
    EXPECT_CALL(boomerangClientMock, AddWatch).WillOnce(Return(RET_OK));
    int32_t ret = boomerangClient.BoomerangDecodeImage(tunnel, pixelMap, callback);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_CALL(boomerangClientMock, RemoveWatch).WillRepeatedly(Return(RET_OK));
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS