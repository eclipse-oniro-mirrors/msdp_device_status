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
MessageParcel data_;
MessageParcel reply_;
StationaryServer stationary_;
uint32_t SUBSCRIBE_STATIONARY_ONE = 1U;
uint32_t SUBSCRIBE_STATIONARY_TWO = 2U;
uint32_t SUBSCRIBE_STATIONARY_THREE = 3U;
#ifndef MOTION_ENABLE
constexpr int32_t RET_NO_SUPPORT = 801;
#endif
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
 * @tc.name: EnableTest001
 * @tc.desc: Test func named enable
 * @tc.type: FUNC
 */
HWTEST_F(StationaryServerTest, EnableTest001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = stationary_.Enable(context_, data_, reply_);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DisableTest001
 * @tc.desc: Test func named disable
 * @tc.type: FUNC
 */
HWTEST_F(StationaryServerTest, DisableTest001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = stationary_.Disable(context_, data_, reply_);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: StartTest001
 * @tc.desc: Test func named start
 * @tc.type: FUNC
 */
HWTEST_F(StationaryServerTest, StartTest001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = stationary_.Start(context_, data_, reply_);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: StopTest001
 * @tc.desc: Test func named stop
 * @tc.type: FUNC
 */
HWTEST_F(StationaryServerTest, StopTest001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = stationary_.Stop(context_, data_, reply_);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: SetParamTest001
 * @tc.desc: Test func named SetParam
 * @tc.type: FUNC
 */
HWTEST_F(StationaryServerTest, SetParamTest001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = stationary_.SetParam(context_, SUBSCRIBE_STATIONARY_ONE, data_, reply_);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: GetParamTest001
 * @tc.desc: Test func named GetParam
 * @tc.type: FUNC
 */
HWTEST_F(StationaryServerTest, GetParamTest001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = stationary_.GetParam(context_, SUBSCRIBE_STATIONARY_ONE, data_, reply_);
    EXPECT_EQ(ret, RET_ERR);
    ret = stationary_.GetParam(context_, SUBSCRIBE_STATIONARY_THREE, data_, reply_);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: GetParamTest002
 * @tc.desc: Test func named GetParam
 * @tc.type: FUNC
 */
HWTEST_F(StationaryServerTest, GetParamTest002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    GetStaionaryDataParam param;
    param.type_ = TYPE_HORIZONTAL_POSITION;
    bool isSuccess = param.Marshalling(data_);
    EXPECT_TRUE(isSuccess);
    int32_t  ret = stationary_.GetParam(context_, SUBSCRIBE_STATIONARY_THREE, data_, reply_);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: ControlTest001
 * @tc.desc: Test func named Control
 * @tc.type: FUNC
 */
HWTEST_F(StationaryServerTest, ControlTest001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = stationary_.Control(context_, SUBSCRIBE_STATIONARY_ONE, data_, reply_);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: AddWatchTest001
 * @tc.desc: Test func named addWatch success
 * @tc.type: FUNC
 */
HWTEST_F(StationaryServerTest, AddWatchTest001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    sptr<IRemoteDevStaCallback> cb = new (std::nothrow) StationaryServerTestCallback();
    ASSERT_NE(cb, nullptr);
    SubscribeStationaryParam param;
    param.type_ = TYPE_HORIZONTAL_POSITION;
    param.event_ = DeviceStatus::ActivityEvent::EVENT_INVALID;
    param.latency_ = DeviceStatus::ReportLatencyNs::Latency_INVALID;
    param.callback_ = cb;
    bool isSuccess = param.Marshalling(data_);
    EXPECT_TRUE(isSuccess);
    int32_t ret = stationary_.AddWatch(context_, SUBSCRIBE_STATIONARY_ONE, data_, reply_);
    EXPECT_EQ(ret, RET_OK);
    UnsubscribeStationaryParam param1;
    param1 = param;
    isSuccess = param1.Marshalling(data_);
    EXPECT_TRUE(isSuccess);
    ret = stationary_.RemoveWatch(context_, SUBSCRIBE_STATIONARY_TWO, data_, reply_);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: AddWatchTest002
 * @tc.desc: Test func named addWatch fail
 * @tc.type: FUNC
 */
HWTEST_F(StationaryServerTest, AddWatchTest002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    SubscribeStationaryParam param;
    param.callback_ = nullptr;
    bool isFalse = param.Marshalling(data_);
    EXPECT_FALSE(isFalse);
    int32_t ret = stationary_.AddWatch(context_, SUBSCRIBE_STATIONARY_ONE, data_, reply_);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: AddWatchTest003
 * @tc.desc: Test func named addWatch fail
 * @tc.type: FUNC
 */
HWTEST_F(StationaryServerTest, AddWatchTest003, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = stationary_.AddWatch(context_, SUBSCRIBE_STATIONARY_TWO, data_, reply_);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: AddWatchTest004
 * @tc.desc: Test func named addWatch success
 * @tc.type: FUNC
 */
HWTEST_F(StationaryServerTest, AddWatchTest004, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    sptr<IRemoteDevStaCallback> cb = new (std::nothrow) StationaryServerTestCallback();
    ASSERT_NE(cb, nullptr);
    SubscribeStationaryParam param;
    param.type_ = TYPE_STAND;
    param.event_ = DeviceStatus::ActivityEvent::EVENT_INVALID;
    param.latency_ = DeviceStatus::ReportLatencyNs::Latency_INVALID;
    param.callback_ = cb;
    bool isSuccess = param.Marshalling(data_);
    EXPECT_TRUE(isSuccess);
    int32_t ret = stationary_.AddWatch(context_, SUBSCRIBE_STATIONARY_ONE, data_, reply_);
#ifdef MOTION_ENABLE
    EXPECT_EQ(ret, RET_OK);
#else
    EXPECT_EQ(ret, RET_NO_SUPPORT);
#endif
    UnsubscribeStationaryParam param1;
    param1 = param;
    isSuccess = param1.Marshalling(data_);
    EXPECT_TRUE(isSuccess);
    ret = stationary_.RemoveWatch(context_, SUBSCRIBE_STATIONARY_TWO, data_, reply_);
#ifdef MOTION_ENABLE
    EXPECT_EQ(ret, RET_OK);
#else
    EXPECT_EQ(ret, RET_NO_SUPPORT);
#endif
}
/**
 * @tc.name: RemoveWatchTest001
 * @tc.desc: Test func named RemoveWatch
 * @tc.type: FUNC
 */
HWTEST_F(StationaryServerTest, RemoveWatchTest001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = stationary_.RemoveWatch(context_, SUBSCRIBE_STATIONARY_ONE, data_, reply_);
    EXPECT_EQ(ret, RET_ERR);
    ret = stationary_.RemoveWatch(context_, SUBSCRIBE_STATIONARY_TWO, data_, reply_);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DumpCurrentDeviceStatusTest001
 * @tc.desc: Test func named DumpCurrentDeviceStatus
 * @tc.type: FUNC
 */
HWTEST_F(StationaryServerTest, DumpCurrentDeviceStatusTest001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t fd = -1;
    stationary_.DumpCurrentDeviceStatus(fd);
    int32_t ret = stationary_.RemoveWatch(context_, SUBSCRIBE_STATIONARY_TWO, data_, reply_);
    EXPECT_EQ(ret, RET_ERR);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS