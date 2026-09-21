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

#include "car_awareness_mgr.h"
#include "car_awareness_type.h"
#include "icar_awareness_callback.h"

using namespace testing::ext;
#undef LOG_TAG
#define LOG_TAG "CarAwarenessMgrTest"
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class CarAwarenessMgrTest : public testing::Test {
public:
    void SetUp(){};
    void TearDown(){};
    static void SetUpTestCase(){};
    static void TearDownTestCase(){};
};

class ICarAwarenessCallbackTest : public ICarAwarenessCallback {
public:
    void OnAwarenessEvent(const CarAwarenessEvent &event) override{}
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

/**
 * @tc.name: CarAwarenessMgrTest_SubscribeCapability_001
 * @tc.desc: Test SubscribeCapability with null callback
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessMgrTest, CarAwarenessMgrTest_SubscribeCapability_001, TestSize.Level1)
{
    CarAwarenessOption option;
    sptr<ICarAwarenessCallback> callback = nullptr;
    auto ret = CarAwarenessMgr::GetInstance().SubscribeCapability(1, option, callback);
    EXPECT_EQ(ret, 401);
}

/**
 * @tc.name: CarAwarenessMgrTest_SubscribeCapability_002
 * @tc.desc: Test SubscribeCapability with valid callback
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessMgrTest, CarAwarenessMgrTest_SubscribeCapability_002, TestSize.Level1)
{
    CarAwarenessOption option;
    sptr<ICarAwarenessCallbackTest> callback = new (std::nothrow) ICarAwarenessCallbackTest();
    ASSERT_NE(callback, nullptr);
    auto ret = CarAwarenessMgr::GetInstance().SubscribeCapability(1, option, callback);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: CarAwarenessMgrTest_UnSubscribeCapability_001
 * @tc.desc: Test UnSubscribeCapability with null callback
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessMgrTest, CarAwarenessMgrTest_UnSubscribeCapability_001, TestSize.Level1)
{
    CarAwarenessOption option;
    sptr<ICarAwarenessCallback> callback = nullptr;
    auto ret = CarAwarenessMgr::GetInstance().UnSubscribeCapability(1, option, callback);
    EXPECT_EQ(ret, 401);
}

/**
 * @tc.name: CarAwarenessMgrTest_UnSubscribeCapability_002
 * @tc.desc: Test UnSubscribeCapability with valid callback
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessMgrTest, CarAwarenessMgrTest_UnSubscribeCapability_002, TestSize.Level1)
{
    CarAwarenessOption option;
    sptr<ICarAwarenessCallbackTest> callback = new (std::nothrow) ICarAwarenessCallbackTest();
    ASSERT_NE(callback, nullptr);
    auto ret = CarAwarenessMgr::GetInstance().UnSubscribeCapability(1, option, callback);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: CarAwarenessMgrTest_GetSupportCapabilityList_001
 * @tc.desc: Test GetSupportCapabilityList
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessMgrTest, CarAwarenessMgrTest_GetSupportCapabilityList_001, TestSize.Level1)
{
    std::vector<std::string> capabilities;
    auto ret = CarAwarenessMgr::GetInstance().GetSupportCapabilityList(capabilities);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: CarAwarenessMgrTest_UpdateSpatialActionZone_001
 * @tc.desc: Test UpdateSpatialActionZone
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessMgrTest, CarAwarenessMgrTest_UpdateSpatialActionZone_001, TestSize.Level1)
{
    int32_t zoneId = 1;
    auto ret = CarAwarenessMgr::GetInstance().UpdateSpatialActionZone(zoneId);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: CarAwarenessMgrTest_UpdateSpatialActionStatus_001
 * @tc.desc: Test UpdateSpatialActionStatus
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessMgrTest, CarAwarenessMgrTest_UpdateSpatialActionStatus_001, TestSize.Level1)
{
    int32_t eventId = 1;
    auto ret = CarAwarenessMgr::GetInstance().UpdateSpatialActionStatus(eventId);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: CarAwarenessMgrTest_GetCarAwareness_001
 * @tc.desc: Test GetCarAwareness
 * @tc.type: FUNC
 */
HWTEST_F(CarAwarenessMgrTest, CarAwarenessMgrTest_GetCarAwareness_001, TestSize.Level1)
{
    CarAwarenessOption option;
    std::vector<CarAwarenessEvent> events;
    auto ret = CarAwarenessMgr::GetInstance().GetCarAwareness(1, option, events);
    EXPECT_TRUE(ret == 0 || ret == -1);
}
}  // namespace DeviceStatus
}  // namespace Msdp
}  // namespace OHOS
