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

#include <gtest/gtest.h>

#include "devicestatus_callback_stub.h"
#include "devicestatus_define.h"
#include "fi_log.h"
#include "stationary_params.h"
#define private public
#include "stationary_server.h"
#undef private
#include "ipc_skeleton.h"

#undef LOG_TAG
#define LOG_TAG "StationaryServerTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
CallingContext context_ {
        .intention = Intention::STATIONARY,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
StationaryServer stationary_;
int32_t TYPE_TYPE_STAND = 7;
int32_t ACTIVITYEVENT_ENTER = 1;
int32_t REPORTLATENCYNS_LATENCY_INVALID = -1;
class StationaryServerTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
public:
    class StationaryServerTestCallback : public DeviceStatusCallbackStub {
    public:
        void OnDeviceStatusChanged(const Data& devicestatusData);
    };
};

void StationaryServerTest::StationaryServerTestCallback::OnDeviceStatusChanged(const
    Data& devicestatusData)
{
    GTEST_LOG_(INFO) << "StationaryServerTestCallback type: " << devicestatusData.type;
    GTEST_LOG_(INFO) << "StationaryServerTestCallback value: " << devicestatusData.value;
    EXPECT_TRUE(devicestatusData.type == Type::TYPE_VERTICAL_POSITION &&
        devicestatusData.value >= OnChangedValue::VALUE_INVALID &&
        devicestatusData.value <= OnChangedValue::VALUE_EXIT) << "StationaryServerTestCallback failed";
}

/**
 * @tc.name: SubscribeStationaryCallbackTest001
 * @tc.desc: Test func named subscribeStationaryCallback
 * @tc.type: FUNC
 */
HWTEST_F(StationaryServerTest, SubscribeStationaryCallbackTest001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    sptr<IRemoteDevStaCallback> callback = new (std::nothrow) StationaryServerTestCallback();
    ASSERT_NE(callback, nullptr);
    int32_t ret = stationary_.SubscribeStationaryCallback(
        context_, TYPE_TYPE_STAND, ACTIVITYEVENT_ENTER, REPORTLATENCYNS_LATENCY_INVALID, callback);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: UnsubscribeStationaryCallbackTest001
 * @tc.desc: Test func named unsubscribeStationaryCallback
 * @tc.type: FUNC
 */
HWTEST_F(StationaryServerTest, UnsubscribeStationaryCallbackTest001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    sptr<IRemoteDevStaCallback> callback = new (std::nothrow) StationaryServerTestCallback();
    ASSERT_NE(callback, nullptr);
    int32_t ret = stationary_.UnsubscribeStationaryCallback(
        context_, TYPE_TYPE_STAND, REPORTLATENCYNS_LATENCY_INVALID, callback);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: GetDeviceStatusDataTest001
 * @tc.desc: Test func named getDeviceStatusData
 * @tc.type: FUNC
 */
HWTEST_F(StationaryServerTest, GetDeviceStatusDataTest001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t replyType;
    int32_t replyValue;
    int32_t ret = stationary_.GetDeviceStatusData(context_, TYPE_TYPE_STAND, replyType, replyValue);
    EXPECT_EQ(ret, RET_OK);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS