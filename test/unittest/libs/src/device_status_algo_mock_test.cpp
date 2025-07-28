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

#include <cstdio>
#include <dlfcn.h>
#include <gtest/gtest.h>

#include <sys/epoll.h>
#include <sys/timerfd.h>

#include "accesstoken_kit.h"
#include "devicestatus_data_define.h"
#include "devicestatus_define.h"
#include "devicestatus_data_parse.h"
#include "devicestatus_msdp_mock.h"
#include "devicestatus_msdp_interface.h"
#include "devicestatus_msdp_mock.h"
#include "devicestatus_msdp_client_impl.h"
#include "sensor_data_callback.h"

#undef LOG_TAG
#define LOG_TAG "DeviceStatusMsdpAlgoMocKTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
std::shared_ptr<DeviceStatusMsdpMock> g_testMock;

} // namespace

class DeviceStatusMsdpAlgoMocKTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
protected:
    DeviceStatusMsdpMock deviceStatusMsdpMock;
};

void DeviceStatusMsdpAlgoMocKTest::SetUpTestCase()
{
    g_testMock = std::make_shared<DeviceStatusMsdpMock>();
}

void DeviceStatusMsdpAlgoMocKTest::TearDownTestCase()
{
    g_testMock = nullptr;
}

void DeviceStatusMsdpAlgoMocKTest::SetUp() {}

void DeviceStatusMsdpAlgoMocKTest::TearDown() {}

/**
 * @tc.name: DeviceStatusMsdpAlgoMocKTest001
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpAlgoMocKTest, DeviceStatusMsdpAlgoMocKTest001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(g_testMock->Init());
    auto callback = std::make_shared<DeviceStatusMsdpClientImpl>();
    EXPECT_TRUE(g_testMock->RegisterCallback(callback) == ERR_OK);
    EXPECT_TRUE(g_testMock->UnregisterCallback() == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMsdpAlgoMocKTest002
 * @tc.desc: test DisableCount
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpAlgoMocKTest, DeviceStatusMsdpAlgoMocKTest002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Type type = (Type)1;
    ErrCode ret = g_testMock->DisableCount(type);
    EXPECT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMsdpAlgoMocKTest005
 * @tc.desc: test SetTimerInterval
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpAlgoMocKTest, DeviceStatusMsdpAlgoMocKTest005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_testMock->timerFd_ = -1;
    int32_t interval = -1;
    EXPECT_TRUE(g_testMock->SetTimerInterval(interval) == RET_ERR);
    g_testMock->timerFd_ = 1;
    EXPECT_TRUE(g_testMock->SetTimerInterval(interval) == RET_ERR);
}

/**
 * @tc.name: DeviceStatusMsdpAlgoMocKTest005
 * @tc.desc: test NotifyMsdpImpl
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpAlgoMocKTest, DeviceStatusMsdpAlgoMocKTest006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct Data data;
    EXPECT_TRUE(g_testMock->NotifyMsdpImpl(data) == RET_ERR);
}

/**
 * @tc.name: DeviceStatusMsdpAlgoMocKTest007
 * @tc.desc: test DisableCount
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpAlgoMocKTest, DeviceStatusMsdpAlgoMocKTest007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Type type = (Type)1;
    g_testMock->dataParse_ = nullptr;
    ErrCode ret = g_testMock->DisableCount(type);
    EXPECT_TRUE(ret == RET_ERR);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS