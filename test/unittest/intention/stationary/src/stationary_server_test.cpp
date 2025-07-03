/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
int32_t RET_NO_SUPPORT = 801;
constexpr float DOUBLEPIMAX = 6.3F;
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
    EXPECT_EQ(ret, RET_NO_SUPPORT);
}

/**
 * @tc.name: SubscribeStationaryCallbackTest002
 * @tc.desc: Test func named subscribeStationaryCallback
 * @tc.type: FUNC
 */
HWTEST_F(StationaryServerTest, SubscribeStationaryCallbackTest002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    sptr<IRemoteDevStaCallback> callback = new (std::nothrow) StationaryServerTestCallback();
    ASSERT_NE(callback, nullptr);
    int32_t ret = stationary_.SubscribeStationaryCallback(
        context_, TYPE_INVALID, ACTIVITYEVENT_ENTER, REPORTLATENCYNS_LATENCY_INVALID, callback);
    EXPECT_EQ(ret, RET_OK);
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
    EXPECT_EQ(ret, RET_NO_SUPPORT);
}

/**
 * @tc.name: UnsubscribeStationaryCallbackTest002
 * @tc.desc: Test func named unsubscribeStationaryCallback
 * @tc.type: FUNC
 */
HWTEST_F(StationaryServerTest, UnsubscribeStationaryCallbackTest002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    sptr<IRemoteDevStaCallback> callback = new (std::nothrow) StationaryServerTestCallback();
    ASSERT_NE(callback, nullptr);
    int32_t ret = stationary_.UnsubscribeStationaryCallback(
        context_, TYPE_INVALID, REPORTLATENCYNS_LATENCY_INVALID, callback);
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

/**
 * @tc.name: GetDevicePosureDataSyncTest001
 * @tc.desc: Test func named GetDevicePosureDataSyncTest001
 * @tc.type: FUNC
 */
HWTEST_F(StationaryServerTest, GetDevicePosureDataSyncTest001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DevicePostureData data;
    int32_t ret = stationary_.GetDevicePostureDataSync(context_, data);
    EXPECT_TRUE(ret == RET_NO_SUPPORT || ret == RET_OK);
    EXPECT_TRUE(data.rollRad >= 0 && data.rollRad <= DOUBLEPIMAX && data.pitchRad >= 0 &&
        data.pitchRad <= DOUBLEPIMAX && data.yawRad >= 0 && data.yawRad <= DOUBLEPIMAX);
}

/**
 * @tc.name: SubscribeStationaryParamTest001
 * @tc.desc: Test func named SubscribeStationaryParam
 * @tc.type: FUNC
 */
HWTEST_F(StationaryServerTest, SubscribeStationaryParamTest001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    Type type = TYPE_ABSOLUTE_STILL;
    ActivityEvent event = ENTER;
    ReportLatencyNs latency = SHORT;
    sptr<IRemoteDevStaCallback> callback = nullptr;
    SubscribeStationaryParam Param = { type, event, latency, callback};
    MessageParcel parcel;
    bool ret = Param.Marshalling(parcel);
    EXPECT_EQ(ret, false);
    ret = Param.Unmarshalling(parcel);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: GetStaionaryDataParamTest001
 * @tc.desc: Test func named GetStaionaryDataParam
 * @tc.type: FUNC
 */
HWTEST_F(StationaryServerTest, GetStaionaryDataParamTest001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    GetStaionaryDataParam param;
    MessageParcel parcel;
    bool ret = param.Marshalling(parcel);
    EXPECT_EQ(ret, true);
    ret = param.Unmarshalling(parcel);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: GetStaionaryDataReplyTest001
 * @tc.desc: Test func named GetStaionaryDataReply
 * @tc.type: FUNC
 */
HWTEST_F(StationaryServerTest, GetStaionaryDataReplyTest001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    Data data;
    GetStaionaryDataReply param {data};
    MessageParcel parcel;
    bool ret = param.Marshalling(parcel);
    EXPECT_EQ(ret, true);
    ret = param.Unmarshalling(parcel);
    EXPECT_EQ(ret, true);
}
/**
 * @tc.name: DumpCurrentDeviceStatusTest001
 * @tc.desc: Test func named DumpCurrentDeviceStatus
 * @tc.type: FUNC
 */
HWTEST_F(StationaryServerTest, DumpCurrentDeviceStatus001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t fd = 1;
    ASSERT_NO_FATAL_FAILURE(stationary_.DumpCurrentDeviceStatus(fd));
}

/**
 * @tc.name: SubscribeTest001
 * @tc.desc: Test func named Subscribe
 * @tc.type: FUNC
 */
HWTEST_F(StationaryServerTest, Subscribe001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    sptr<IRemoteDevStaCallback> callback = new (std::nothrow) StationaryServerTestCallback();
    ASSERT_NE(callback, nullptr);
    ActivityEvent stationaryEvent = static_cast<ActivityEvent>(ACTIVITYEVENT_ENTER);
    ReportLatencyNs stationaryLatency = static_cast<ReportLatencyNs>(REPORTLATENCYNS_LATENCY_INVALID);
    ASSERT_NO_FATAL_FAILURE(stationary_.Subscribe(
        context_, TYPE_INVALID, stationaryEvent, stationaryLatency, callback));
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS