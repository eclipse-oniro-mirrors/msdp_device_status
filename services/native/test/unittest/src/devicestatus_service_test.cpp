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

#include "devicestatus_service_test.h"

#include <iostream>
#include <chrono>
#include <thread>
#include <gtest/gtest.h>
#include <if_system_ability_manager.h>
#include <ipc_skeleton.h>
#include <string_ex.h>

#include "devicestatus_common.h"
#include "devicestatus_dumper.h"
#include "stationary_manager.h"

using namespace testing::ext;
using namespace OHOS::Msdp::DeviceStatus;
using namespace OHOS;
using namespace std;

namespace {
const int32_t SLEEP_TIME = 2000;
static Type g_type = Type::TYPE_INVALID;
auto g_client = StationaryManager::GetInstance();
}

sptr<IRemoteDevStaCallback> DeviceStatusServiceTest::devCallback_ = nullptr;

void DeviceStatusServiceTest::SetUpTestCase()
{
    devCallback_ = new (std::nothrow) DeviceStatusServiceTestCallback();
}

void DeviceStatusServiceTest::TearDownTestCase() {}

void DeviceStatusServiceTest::SetUp() {}

void DeviceStatusServiceTest::TearDown() {}

void DeviceStatusServiceTest::DeviceStatusServiceTestCallback::OnDeviceStatusChanged(const Data& devicestatusData)
{
    GTEST_LOG_(INFO) << "DeviceStatusServiceTestCallback type: " << devicestatusData.type;
    GTEST_LOG_(INFO) << "DeviceStatusServiceTestCallback value: " << devicestatusData.value;
    EXPECT_TRUE(devicestatusData.type == g_type && (devicestatusData.value >= OnChangedValue::VALUE_INVALID &&
        devicestatusData.value <= OnChangedValue::VALUE_EXIT)) << "DeviceStatusServiceTestCallback failed";
}

/**
 * @tc.name: DeviceStatusCallbackTest
 * @tc.desc: test devicestatus callback in proxy
 * @tc.type: FUNC
 */
HWTEST_F (DeviceStatusServiceTest, DeviceStatusCallbackTest001, TestSize.Level0)
{
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest001 Enter");
    g_type = Type::TYPE_ABSOLUTE_STILL;
    EXPECT_FALSE(devCallback_ == nullptr);
    GTEST_LOG_(INFO) << "Start register";
    g_client->SubscribeCallback(g_type, ActivityEvent::ENTER_EXIT, ReportLatencyNs::LONG, devCallback_);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest001 end");
}

/**
 * @tc.name: GetDeviceStatusDataTest
 * @tc.desc: test get devicestatus data in proxy
 * @tc.type: FUNC
 */
HWTEST_F (DeviceStatusServiceTest, GetDeviceStatusDataTest002, TestSize.Level0)
{
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest002 Enter");
    g_type = Type::TYPE_ABSOLUTE_STILL;
    Data data = g_client->GetDeviceStatusData(g_type);
    GTEST_LOG_(INFO) << "type: " << data.type;
    GTEST_LOG_(INFO) << "value: " << data.value;
    EXPECT_TRUE(data.type == Type::TYPE_ABSOLUTE_STILL &&
        (data.value >= OnChangedValue::VALUE_ENTER && data.value <= OnChangedValue::VALUE_EXIT))
        << "GetDeviceStatusData failed";
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest002 end");
}

/**
 * @tc.name: GetDeviceStatusDataTest
 * @tc.desc: test get devicestatus data in proxy
 * @tc.type: FUNC
 */
HWTEST_F (DeviceStatusServiceTest, GetDeviceStatusDataTest003, TestSize.Level0)
{
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest003 Enter");
    g_type = Type::TYPE_ABSOLUTE_STILL;
    EXPECT_FALSE(devCallback_ == nullptr);
    GTEST_LOG_(INFO) << "Cancel register";
    g_client->UnsubscribeCallback(g_type, ActivityEvent::ENTER_EXIT, devCallback_);
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest003 end");
}

/**
 * @tc.name: DeviceStatusCallbackTest
 * @tc.desc: test devicestatus callback in proxy
 * @tc.type: FUNC
 */
HWTEST_F (DeviceStatusServiceTest, DeviceStatusCallbackTest004, TestSize.Level0)
{
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest004 Enter");
    g_type = Type::TYPE_CAR_BLUETOOTH;
    EXPECT_FALSE(devCallback_ == nullptr);
    GTEST_LOG_(INFO) << "Start register";
    g_client->SubscribeCallback(g_type, ActivityEvent::ENTER_EXIT, ReportLatencyNs::LONG, devCallback_);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest004 end");
}

/**
 * @tc.name: GetDeviceStatusDataTest
 * @tc.desc: test get devicestatus data in proxy
 * @tc.type: FUNC
 */
HWTEST_F (DeviceStatusServiceTest, GetDeviceStatusDataTest005, TestSize.Level0)
{
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest005 Enter");
    g_type = Type::TYPE_CAR_BLUETOOTH;
    Data data = g_client->GetDeviceStatusData(g_type);
    GTEST_LOG_(INFO) << "type: " << data.type;
    GTEST_LOG_(INFO) << "value: " << data.value;
    EXPECT_TRUE(data.type == Type::TYPE_CAR_BLUETOOTH &&
        (data.value <= OnChangedValue::VALUE_EXIT && data.value >= OnChangedValue::VALUE_INVALID))
        << "GetDeviceStatusData failed";
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest005 end");
}

/**
 * @tc.name: GetDeviceStatusDataTest
 * @tc.desc: test get devicestatus data in proxy
 * @tc.type: FUNC
 */
HWTEST_F (DeviceStatusServiceTest, GetDeviceStatusDataTest006, TestSize.Level0)
{
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest006 Enter");
    g_type = Type::TYPE_CAR_BLUETOOTH;
    EXPECT_FALSE(devCallback_ == nullptr);
    GTEST_LOG_(INFO) << "Cancel register";
    g_client->UnsubscribeCallback(g_type, ActivityEvent::ENTER_EXIT, devCallback_);
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest006 end");
}

/**
 * @tc.name: DeviceStatusCallbackTest
 * @tc.desc: test devicestatus callback in proxy
 * @tc.type: FUNC
 */
HWTEST_F (DeviceStatusServiceTest, DeviceStatusCallbackTest007, TestSize.Level0)
{
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest007 Enter");
    g_type = Type::TYPE_HORIZONTAL_POSITION;
    EXPECT_FALSE(devCallback_ == nullptr);
    GTEST_LOG_(INFO) << "Start register";
    g_client->SubscribeCallback(g_type, ActivityEvent::ENTER_EXIT, ReportLatencyNs::LONG, devCallback_);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest007 end");
}

/**
 * @tc.name: GetDeviceStatusDataTest
 * @tc.desc: test get devicestatus data in proxy
 * @tc.type: FUNC
 */
HWTEST_F (DeviceStatusServiceTest, GetDeviceStatusDataTest008, TestSize.Level0)
{
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest008 Enter");
    g_type = Type::TYPE_HORIZONTAL_POSITION;
    Data data = g_client->GetDeviceStatusData(g_type);
    GTEST_LOG_(INFO) << "type: " << data.type;
    GTEST_LOG_(INFO) << "value: " << data.value;
    EXPECT_TRUE(data.type == Type::TYPE_HORIZONTAL_POSITION &&
        (data.value >= OnChangedValue::VALUE_ENTER && data.value <= OnChangedValue::VALUE_EXIT))
        << "GetDeviceStatusData failed";
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest008 end");
}

/**
 * @tc.name: GetDeviceStatusDataTest
 * @tc.desc: test get devicestatus data in proxy
 * @tc.type: FUNC
 */
HWTEST_F (DeviceStatusServiceTest, GetDeviceStatusDataTest009, TestSize.Level0)
{
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest009 Enter");
    g_type = Type::TYPE_HORIZONTAL_POSITION;
    EXPECT_FALSE(devCallback_ == nullptr);
    GTEST_LOG_(INFO) << "Cancel register";
    g_client->UnsubscribeCallback(g_type, ActivityEvent::ENTER_EXIT, devCallback_);
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest009 end");
}

/**
 * @tc.name: DeviceStatusCallbackTest
 * @tc.desc: test devicestatus callback in proxy
 * @tc.type: FUNC
 */
HWTEST_F (DeviceStatusServiceTest, DeviceStatusCallbackTest010, TestSize.Level0)
{
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest010 Enter");
    g_type = Type::TYPE_RELATIVE_STILL;
    EXPECT_FALSE(devCallback_ == nullptr);
    GTEST_LOG_(INFO) << "Start register";
    g_client->SubscribeCallback(g_type, ActivityEvent::ENTER_EXIT, ReportLatencyNs::LONG, devCallback_);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest010 end");
}

/**
 * @tc.name: GetDeviceStatusDataTest
 * @tc.desc: test get devicestatus data in proxy
 * @tc.type: FUNC
 */
HWTEST_F (DeviceStatusServiceTest, GetDeviceStatusDataTest011, TestSize.Level0)
{
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest011 Enter");
    g_type = Type::TYPE_RELATIVE_STILL;
    Data data = g_client->GetDeviceStatusData(g_type);
    GTEST_LOG_(INFO) << "type: " << data.type;
    GTEST_LOG_(INFO) << "value: " << data.value;
    EXPECT_TRUE(data.type == Type::TYPE_RELATIVE_STILL &&
        (data.value <= OnChangedValue::VALUE_EXIT && data.value >= OnChangedValue::VALUE_INVALID))
        << "GetDeviceStatusData failed";
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest011 end");
}

/**
 * @tc.name: GetDeviceStatusDataTest
 * @tc.desc: test get devicestatus data in proxy
 * @tc.type: FUNC
 */
HWTEST_F (DeviceStatusServiceTest, GetDeviceStatusDataTest012, TestSize.Level0)
{
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest012 Enter");
    g_type = Type::TYPE_RELATIVE_STILL;
    EXPECT_FALSE(devCallback_ == nullptr);
    GTEST_LOG_(INFO) << "Cancel register";
    g_client->UnsubscribeCallback(g_type, ActivityEvent::ENTER_EXIT, devCallback_);
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest012 end");
}

/**
 * @tc.name: DeviceStatusCallbackTest
 * @tc.desc: test devicestatus callback in proxy
 * @tc.type: FUNC
 */
HWTEST_F (DeviceStatusServiceTest, DeviceStatusCallbackTest013, TestSize.Level0)
{
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest013 Enter");
    g_type = Type::TYPE_STILL;
    EXPECT_FALSE(devCallback_ == nullptr);
    GTEST_LOG_(INFO) << "Start register";
    g_client->SubscribeCallback(g_type, ActivityEvent::ENTER_EXIT, ReportLatencyNs::LONG, devCallback_);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest013 end");
}

/**
 * @tc.name: GetDeviceStatusDataTest
 * @tc.desc: test get devicestatus data in proxy
 * @tc.type: FUNC
 */
HWTEST_F (DeviceStatusServiceTest, GetDeviceStatusDataTest014, TestSize.Level0)
{
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest014 Enter");
    g_type = Type::TYPE_STILL;
    Data data = g_client->GetDeviceStatusData(g_type);
    GTEST_LOG_(INFO) << "type: " << data.type;
    GTEST_LOG_(INFO) << "value: " << data.value;
    EXPECT_TRUE(data.type == Type::TYPE_STILL &&
        (data.value <= OnChangedValue::VALUE_EXIT && data.value >= OnChangedValue::VALUE_INVALID))
        << "GetDeviceStatusData failed";
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest014 end");
}

/**
 * @tc.name: GetDeviceStatusDataTest
 * @tc.desc: test get devicestatus data in proxy
 * @tc.type: FUNC
 */
HWTEST_F (DeviceStatusServiceTest, GetDeviceStatusDataTest015, TestSize.Level0)
{
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest015 Enter");
    g_type = Type::TYPE_STILL;
    EXPECT_FALSE(devCallback_ == nullptr);
    GTEST_LOG_(INFO) << "Cancel register";
    g_client->UnsubscribeCallback(g_type, ActivityEvent::ENTER_EXIT, devCallback_);
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest015 end");
}

/**
 * @tc.name: DeviceStatusCallbackTest
 * @tc.desc: test devicestatus callback in proxy
 * @tc.type: FUNC
 */
HWTEST_F (DeviceStatusServiceTest, DeviceStatusCallbackTest016, TestSize.Level0)
{
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest016 Enter");
    g_type = Type::TYPE_VERTICAL_POSITION;
    EXPECT_FALSE(devCallback_ == nullptr);
    GTEST_LOG_(INFO) << "Start register";
    g_client->SubscribeCallback(g_type, ActivityEvent::ENTER_EXIT, ReportLatencyNs::LONG, devCallback_);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest016 end");
}

/**
 * @tc.name: GetDeviceStatusDataTest
 * @tc.desc: test get devicestatus data in proxy
 * @tc.type: FUNC
 */
HWTEST_F (DeviceStatusServiceTest, GetDeviceStatusDataTest017, TestSize.Level0)
{
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest017 Enter");
    g_type = Type::TYPE_VERTICAL_POSITION;
    Data data = g_client->GetDeviceStatusData(g_type);
    GTEST_LOG_(INFO) << "type: " << data.type;
    GTEST_LOG_(INFO) << "value: " << data.value;
    EXPECT_TRUE(data.type == Type::TYPE_VERTICAL_POSITION &&
        (data.value >= OnChangedValue::VALUE_INVALID && data.value <= OnChangedValue::VALUE_EXIT))
        << "GetDeviceStatusData failed";
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest017 end");
}

/**
 * @tc.name: GetDeviceStatusDataTest
 * @tc.desc: test get devicestatus data in proxy
 * @tc.type: FUNC
 */
HWTEST_F (DeviceStatusServiceTest, GetDeviceStatusDataTest018, TestSize.Level0)
{
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest018 Enter");
    g_type = Type::TYPE_VERTICAL_POSITION;
    EXPECT_FALSE(devCallback_ == nullptr);
    GTEST_LOG_(INFO) << "Cancel register";
    g_client->UnsubscribeCallback(g_type, ActivityEvent::ENTER_EXIT, devCallback_);
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest018 end");
}

/**
 * @tc.name: GetDeviceStatusDataTest
 * @tc.desc: test get devicestatus data in proxy
 * @tc.type: FUNC
 */
HWTEST_F (DeviceStatusServiceTest, GetDeviceStatusDataTest019, TestSize.Level0)
{
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest019 Enter");
    g_type = Type::TYPE_VERTICAL_POSITION;
    Data data = g_client->GetDeviceStatusData(g_type);
    GTEST_LOG_(INFO) << "type: " << data.type;
    GTEST_LOG_(INFO) << "value: " << data.value;
    EXPECT_TRUE(data.type == Type::TYPE_VERTICAL_POSITION &&
        (data.value >= OnChangedValue::VALUE_INVALID && data.value <= OnChangedValue::VALUE_EXIT))
        << "GetDeviceStatusData failed";
    Data InvalidData;
    InvalidData.type = Type::TYPE_INVALID;
    InvalidData.value = OnChangedValue::VALUE_INVALID;
    InvalidData.status = Status::STATUS_INVALID;
    InvalidData.movement = 0.0f;
    EXPECT_TRUE(data != InvalidData);
    DEV_HILOGI(SERVICE, "GetDeviceStatusDataTest019 end");
}
