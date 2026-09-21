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

#include "devicestatus_define.h"
#include "fi_log.h"
#include "car_awareness_type.h"
#include "car_awareness_client.h"
#include "car_awareness_server_test.h"

#undef LOG_TAG
#define LOG_TAG "CarAwarenessClientTest"

#ifdef DEVICE_STATUS_CAR_AWARENESS_ENABLE
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
constexpr int32_t TYPE_CAR_STATUS = 203;
constexpr int32_t INVALID_PARAM = 401;

namespace {
class MockCarAwarenessClientTestCallback : public CarAwarenessCallbackStub {
public:
    void OnAwarenessEvent(const CarAwarenessEvent &event) override
    {
        FI_HILOGI("OnAwarenessEvent called, type:%{public}d", event.type);
    }
};
} // namespace

void CarAwarenessClientTest::SetUpTestCase()
{
    FI_HILOGI("SetUpTestCase");
}

void CarAwarenessClientTest::TearDownTestCase()
{
    FI_HILOGI("TearDownTestCase");
}

void CarAwarenessClientTest::SetUp()
{
    FI_HILOGI("SetUp");
}

void CarAwarenessClientTest::TearDown()
{
    FI_HILOGI("TearDown");
}

HWTEST_F(CarAwarenessClientTest, Constructor001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessClient client;
    EXPECT_TRUE(true);
}

HWTEST_F(CarAwarenessClientTest, SubscribeCapability001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessClient client;
    CarAwarenessOption option;
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) MockCarAwarenessClientTestCallback();
    ASSERT_NE(cb, nullptr);
    int32_t ret = client.SubscribeCapability(TYPE_CAR_STATUS, option, cb);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
}

HWTEST_F(CarAwarenessClientTest, SubscribeCapability002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessClient client;
    CarAwarenessOption option;
    sptr<ICarAwarenessCallback> cb = nullptr;
    int32_t ret = client.SubscribeCapability(TYPE_CAR_STATUS, option, cb);
    EXPECT_EQ(ret, INVALID_PARAM);
}

HWTEST_F(CarAwarenessClientTest, UnSubscribeCapability001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessClient client;
    CarAwarenessOption option;
    sptr<ICarAwarenessCallback> cb = new (std::nothrow) MockCarAwarenessClientTestCallback();
    ASSERT_NE(cb, nullptr);
    int32_t ret = client.UnSubscribeCapability(TYPE_CAR_STATUS, option, cb);
    EXPECT_EQ(ret, RET_OK);
}

HWTEST_F(CarAwarenessClientTest, UnSubscribeCapability002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessClient client;
    CarAwarenessOption option;
    sptr<ICarAwarenessCallback> cb = nullptr;
    int32_t ret = client.UnSubscribeCapability(TYPE_CAR_STATUS, option, cb);
    EXPECT_EQ(ret, INVALID_PARAM);
}

HWTEST_F(CarAwarenessClientTest, UpdateSpatialActionStatus001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessClient client;
    int32_t ret = client.UpdateSpatialActionStatus(1);
    EXPECT_NE(ret, RET_OK);
}

HWTEST_F(CarAwarenessClientTest, UpdateSpatialActionStatus002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessClient client;
    int32_t ret = client.UpdateSpatialActionStatus(0);
    EXPECT_NE(ret, RET_OK);
}

HWTEST_F(CarAwarenessClientTest, UpdateSpatialActionZone001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessClient client;
    int32_t ret = client.UpdateSpatialActionZone(1);
    EXPECT_NE(ret, RET_OK);
}

HWTEST_F(CarAwarenessClientTest, UpdateSpatialActionZone002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessClient client;
    int32_t ret = client.UpdateSpatialActionZone(0);
    EXPECT_NE(ret, RET_OK);
}

HWTEST_F(CarAwarenessClientTest, GetSupportCapabilityList001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessClient client;
    std::vector<std::string> capabilities;
    int32_t ret = client.GetSupportCapabilityList(capabilities);
    EXPECT_EQ(ret, RET_OK);
}

HWTEST_F(CarAwarenessClientTest, GetSupportCapabilityList002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessClient client;
    std::vector<std::string> capabilities;
    capabilities.emplace_back("test");
    int32_t ret = client.GetSupportCapabilityList(capabilities);
    EXPECT_EQ(ret, RET_OK);
}

HWTEST_F(CarAwarenessClientTest, GetCarAwareness001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessClient client;
    CarAwarenessOption option;
    std::vector<CarAwarenessEvent> events;
    int32_t ret = client.GetCarAwareness(TYPE_CAR_STATUS, option, events);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
}

HWTEST_F(CarAwarenessClientTest, GetCarAwareness002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CarAwarenessClient client;
    CarAwarenessOption option;
    std::vector<CarAwarenessEvent> events;
    CarAwarenessEvent event;
    event.type = TYPE_CAR_STATUS;
    events.push_back(event);
    int32_t ret = client.GetCarAwareness(TYPE_CAR_STATUS, option, events);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DEVICE_STATUS_CAR_AWARENESS_ENABLE
