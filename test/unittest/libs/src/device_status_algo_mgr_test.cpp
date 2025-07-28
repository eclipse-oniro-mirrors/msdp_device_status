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

#ifdef DEVICE_STATUS_SENSOR_ENABLE
#include <memory>
#include <dlfcn.h>

#include <gtest/gtest.h>

#include "accesstoken_kit.h"
#include "devicestatus_define.h"
#include "devicestatus_algorithm_manager.h"
#include "sensor_agent_type.h"
#include "sensor_data_callback.h"
#include "stationary_data.h"
#include "devicestatus_dumper.h"
#include "devicestatus_manager.h"

#undef LOG_TAG
#define LOG_TAG "DeviceStatusAlgoMgrTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
std::shared_ptr<AlgoMgr> g_algoManager { nullptr };
} // namespace

class DeviceStatusAlgoMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DeviceStatusAlgoMgrTest::SetUpTestCase()
{
    g_algoManager = std::make_shared<AlgoMgr>();
}

void DeviceStatusAlgoMgrTest::TearDownTestCase()
{
    g_algoManager = nullptr;
}

void DeviceStatusAlgoMgrTest::SetUp() {}

void DeviceStatusAlgoMgrTest::DeviceStatusAlgoMgrTest::TearDown() {}


/**
 * @tc.name: DeviceStatusAlgoMgrTest001
 * @tc.desc: test GetSensorTypeId
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusAlgoMgrTest, DeviceStatusAlgoMgrTest001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Type type = Type::TYPE_HORIZONTAL_POSITION;
    int32_t result = g_algoManager->GetSensorTypeId(type);
    EXPECT_TRUE(result);
    type = (Type)-1;
    result = g_algoManager->GetSensorTypeId(type);
    EXPECT_TRUE(result == RET_ERR);
}

/**
 * @tc.name: DeviceStatusAlgoMgrTest002
 * @tc.desc: test DisableCount
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusAlgoMgrTest, DeviceStatusAlgoMgrTest002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Type type = (Type)1;
    bool result = g_algoManager->DisableCount(type);
    EXPECT_TRUE(result == RET_OK);
}

/**
 * @tc.name: DeviceStatusAlgoMgrTest003
 * @tc.desc: test UnregisterCallback
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusAlgoMgrTest, DeviceStatusAlgoMgrTest003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool result = g_algoManager->UnregisterCallback();
    EXPECT_TRUE(result == RET_OK);
}

/**
 * @tc.name: DeviceStatusAlgoMgrTest004
 * @tc.desc: test CheckSensorTypeId
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusAlgoMgrTest, DeviceStatusAlgoMgrTest004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t sensorTypeId = SENSOR_TYPE_ID_MAX;
    int32_t ret = g_algoManager->CheckSensorTypeId(sensorTypeId);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: DeviceStatusAlgoMgrTest005
 * @tc.desc: test CheckSensorTypeId
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusAlgoMgrTest, DeviceStatusAlgoMgrTest005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t sensorTypeId = SENSOR_TYPE_ID_MAX;
    int32_t ret = g_algoManager->CheckSensorTypeId(sensorTypeId);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: DeviceStatusAlgoMgrTest006
 * @tc.desc: test Enable
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusAlgoMgrTest, DeviceStatusAlgoMgrTest006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Type type = Type::TYPE_VERTICAL_POSITION;
    int32_t ret = g_algoManager->Enable(type);
    EXPECT_FALSE(ret);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DEVICE_STATUS_SENSOR_ENABLE
