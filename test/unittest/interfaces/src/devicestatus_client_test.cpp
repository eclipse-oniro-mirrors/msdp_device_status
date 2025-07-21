/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include <vector>

#include "devicestatus_callback_stub.h"
#include "devicestatus_define.h"
#include "on_screen_data.h"
#include "on_screen_manager.h"
#include "stationary_manager.h"

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

#undef LOG_TAG
#define LOG_TAG "DeviceStatusClientTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
using namespace Security::AccessToken;
namespace {
constexpr float DOUBLEPIMAX = 6.3F;
constexpr int32_t RET_NO_SUPPORT = 801;
uint64_t tokenId_ = 0;
const char *PERMISSION_GET_PAGE_CONTENT = "ohos.permission.GET_SCREEN_CONTENT";
const char *PERMISSION_SEND_CONTROL_EVENT = "ohos.permission.SIMULATE_USER_INPUT";
}

class DeviceStatusClientTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    class DeviceStatusClientTestCallback : public DeviceStatusCallbackStub {
    public:
        DeviceStatusClientTestCallback() {};
        virtual ~DeviceStatusClientTestCallback() {};
        virtual void OnDeviceStatusChanged(const Data& devicestatusData);
    };
};

void DeviceStatusClientTest::SetUp() {}

void DeviceStatusClientTest::TearDown() {}

void DeviceStatusClientTest::SetUpTestCase()
{
    const char **perms = new (std::nothrow) const char *[2];
    const char **acls = new (std::nothrow) const char *[2];
    if (perms == nullptr || acls == nullptr) {
        return;
    }
    perms[0] = PERMISSION_GET_PAGE_CONTENT;
    perms[1] = PERMISSION_SEND_CONTROL_EVENT;
    acls[0] = PERMISSION_GET_PAGE_CONTENT;
    acls[1] = PERMISSION_SEND_CONTROL_EVENT;
    TokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 2,
        .dcaps = nullptr,
        .perms = perms,
        .acls = acls,
        .processName = "DeviceStatusClientTest",
        .aplStr = "system_core",
    };
    tokenId_ = GetAccessTokenId(&infoInstance);
    ASSERT_EQ(SetSelfTokenID(tokenId_), 0);
    AccessTokenKit::ReloadNativeTokenInfo();
}

void DeviceStatusClientTest::TearDownTestCase()
{
    int32_t ret = AccessTokenKit::DeleteToken(tokenId_);
    if (ret != RET_OK) {
        FI_HILOGE("failed to remove permission");
        return;
    }
}

void DeviceStatusClientTest::DeviceStatusClientTestCallback::OnDeviceStatusChanged(const
    Data& devicestatusData)
{
    GTEST_LOG_(INFO) << "DeviceStatusClientTestCallback type: " << devicestatusData.type;
    GTEST_LOG_(INFO) << "DeviceStatusClientTestCallback value: " << devicestatusData.value;
    EXPECT_TRUE(devicestatusData.type == Type::TYPE_VERTICAL_POSITION &&
        devicestatusData.value >= OnChangedValue::VALUE_INVALID &&
        devicestatusData.value <= OnChangedValue::VALUE_EXIT) << "DeviceStatusClientTestCallback failed";
}

/**
 * @tc.name: DeviceStatusCallbackTest001
 * @tc.desc: test devicestatus callback in proxy
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusClientTest, DeviceStatusCallbackTest001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    sptr<IRemoteDevStaCallback> cb = new (std::nothrow) DeviceStatusClientTestCallback();
    ASSERT_NE(cb, nullptr);
    StationaryManager& stationaryMgr = StationaryManager::GetInstance();
    ReportLatencyNs latency = ReportLatencyNs::Latency_INVALID;
    ActivityEvent activityEvent = ActivityEvent::EVENT_INVALID;
    int32_t result = stationaryMgr.SubscribeCallback(Type::TYPE_VERTICAL_POSITION, activityEvent, latency, cb);
    ASSERT_EQ(result, RET_OK);
    result = stationaryMgr.UnsubscribeCallback(Type::TYPE_VERTICAL_POSITION, activityEvent, cb);
    ASSERT_EQ(result, RET_OK);

    result = stationaryMgr.SubscribeCallback(Type::TYPE_INVALID, activityEvent, latency, cb);
    ASSERT_EQ(result, RET_OK);
    result = stationaryMgr.UnsubscribeCallback(Type::TYPE_INVALID, activityEvent, cb);
    ASSERT_EQ(result, RET_OK);

    result = stationaryMgr.SubscribeCallback(Type::TYPE_ABSOLUTE_STILL, activityEvent, latency, cb);
    ASSERT_EQ(result, RET_OK);
    result = stationaryMgr.UnsubscribeCallback(Type::TYPE_ABSOLUTE_STILL, activityEvent, cb);
    ASSERT_EQ(result, RET_OK);

    result = stationaryMgr.SubscribeCallback(Type::TYPE_HORIZONTAL_POSITION, activityEvent, latency, cb);
    ASSERT_EQ(result, RET_OK);
    result = stationaryMgr.UnsubscribeCallback(Type::TYPE_HORIZONTAL_POSITION, activityEvent, cb);
    ASSERT_EQ(result, RET_OK);

    result = stationaryMgr.SubscribeCallback(Type::TYPE_LID_OPEN, activityEvent, latency, cb);
    ASSERT_EQ(result, RET_OK);
    result = stationaryMgr.UnsubscribeCallback(Type::TYPE_LID_OPEN, activityEvent, cb);
    ASSERT_EQ(result, RET_OK);

    result = stationaryMgr.SubscribeCallback(Type::TYPE_MAX, activityEvent, latency, cb);
    ASSERT_EQ(result, RET_OK);
    result = stationaryMgr.UnsubscribeCallback(Type::TYPE_MAX, activityEvent, cb);
    ASSERT_EQ(result, RET_OK);
}

/**
 * @tc.name: GetDeviceStatusDataTest001
 * @tc.desc: test get devicestatus data in proxy
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusClientTest, GetDeviceStatusDataTest001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    StationaryManager& stationaryMgr = StationaryManager::GetInstance();
    OnChangedValue invalidValue = OnChangedValue::VALUE_INVALID;
    OnChangedValue exitValue = OnChangedValue::VALUE_EXIT;

    Type type = Type::TYPE_ABSOLUTE_STILL;
    Data data = stationaryMgr.GetDeviceStatusData(type);
    EXPECT_TRUE(data.type == type && data.value >= invalidValue && data.value <= exitValue);

    type = Type::TYPE_VERTICAL_POSITION;
    data = stationaryMgr.GetDeviceStatusData(type);
    EXPECT_TRUE(data.type == type && data.value >= invalidValue && data.value <= exitValue);

    type = Type::TYPE_HORIZONTAL_POSITION;
    data = stationaryMgr.GetDeviceStatusData(type);
    EXPECT_TRUE(data.type == type && data.value >= invalidValue && data.value <= exitValue);

    type = Type::TYPE_LID_OPEN;
    data = stationaryMgr.GetDeviceStatusData(type);
    EXPECT_TRUE(data.type == type && data.value >= invalidValue && data.value <= exitValue);

    type = Type::TYPE_INVALID;
    data = stationaryMgr.GetDeviceStatusData(type);
    EXPECT_TRUE(data.type == type && data.value >= invalidValue && data.value <= exitValue);

    type = static_cast<Type>(10);
    data = stationaryMgr.GetDeviceStatusData(type);
    EXPECT_TRUE(data.type == type && data.value >= invalidValue && data.value <= exitValue);
}

/**
 * @tc.name: GetDevicePostureDataSync001
 * @tc.desc: test GetDevicePostureDataSync in proxy
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusClientTest, GetDevicePostureDataSyncTest001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    StationaryManager& stationaryMgr = StationaryManager::GetInstance();
    DevicePostureData data;
    int32_t ret = stationaryMgr.GetDevicePostureDataSync(data);
    EXPECT_TRUE(ret == RET_OK || ret == RET_NO_SUPPORT);
    EXPECT_TRUE(data.rollRad >= 0 && data.rollRad <= DOUBLEPIMAX && data.pitchRad >= 0 &&
        data.pitchRad <= DOUBLEPIMAX && data.yawRad >= 0 && data.yawRad <= DOUBLEPIMAX);
    ret = stationaryMgr.GetDevicePostureDataSync(data);
    EXPECT_TRUE(ret == RET_OK || ret == RET_NO_SUPPORT);
    EXPECT_TRUE(data.rollRad >= 0 && data.rollRad <= DOUBLEPIMAX && data.pitchRad >= 0 &&
        data.pitchRad <= DOUBLEPIMAX && data.yawRad >= 0 && data.yawRad <= DOUBLEPIMAX);
    ret = stationaryMgr.GetDevicePostureDataSync(data);
    EXPECT_TRUE(ret == RET_OK || ret == RET_NO_SUPPORT);
    EXPECT_TRUE(data.rollRad >= 0 && data.rollRad <= DOUBLEPIMAX && data.pitchRad >= 0 &&
        data.pitchRad <= DOUBLEPIMAX && data.yawRad >= 0 && data.yawRad <= DOUBLEPIMAX);
}

/**
 * @tc.name: GetPageContent001
 * @tc.desc: test GetPageContent001
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusClientTest, GetPageContent001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    OnScreen::ContentOption option;
    option.contentUnderstand = true;
    option.pageLink = true;
    option.textOnly = true;
    OnScreen::PageContent pageContent;
    int32_t ret = OnScreen::OnScreenManager::GetInstance().GetPageContent(option, pageContent);
    std::cout << "windowId:" << pageContent.windowId << std::endl;
    std::cout << "bundleName:" << pageContent.bundleName << std::endl;
    std::cout << "title:" << pageContent.title << std::endl;
    std::cout << "content:" << pageContent.content << std::endl;
    std::cout << "pageLink:" << pageContent.pageLink << std::endl;
    std::cout << "paragraphs:" << std::endl;
    for (auto i = 0; i < pageContent.paragraphs.size(); i++) {
        std::cout << "------pagegragh " << i << "---------" << std::endl;
        std::cout << "hookid: "<< pageContent.paragraphs[i].hookId << std::endl;
        std::cout << "title: "<< pageContent.paragraphs[i].title << std::endl;
        std::cout << "content: "<< pageContent.paragraphs[i].content << std::endl;
    }
    std::cout << "--------------------------" << std::endl;
    std::cout << "ret:" << ret << std::endl;
    EXPECT_TRUE(ret >= RET_ERR);
}

/**
 * @tc.name: GetPageContent001
 * @tc.desc: test GetPageContent001
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusClientTest, SendControlEvent, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    OnScreen::ControlEvent event;
    event.eventType = OnScreen::EventType::END;
    int32_t ret = OnScreen::OnScreenManager::GetInstance().SendControlEvent(event);
    EXPECT_TRUE(ret >= RET_ERR);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
