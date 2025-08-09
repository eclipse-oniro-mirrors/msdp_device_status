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

#include "devicestatus_msdp_client_impl_test.h"

#include <chrono>
#include <iostream>
#include <thread>

#include <if_system_ability_manager.h>
#include <ipc_skeleton.h>
#include <securec.h>

#include "devicestatus_msdp_client_impl.h"
#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "DeviceStatusMsdpClientImplTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;

void DeviceStatusMsdpClientImplTest::SetUpTestCase() {}

void DeviceStatusMsdpClientImplTest::TearDownTestCase() {}

void DeviceStatusMsdpClientImplTest::SetUp() {}

void DeviceStatusMsdpClientImplTest::TearDown() {}

namespace {
/**
 * @tc.name: DeviceStatusMsdpClientImplTest
 * @tc.desc: test devicestatus impl
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMsdpClientImplTest, DeviceStatusMsdpClientImplTest, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "DeviceStatusMsdpClientImplTest start";
    auto msdpImpl = std::make_shared<DeviceStatusMsdpClientImpl>();
    Data data = {Type::TYPE_RELATIVE_STILL, OnChangedValue::VALUE_ENTER};
    msdpImpl->MsdpCallback(data);
    ASSERT_NE(msdpImpl, nullptr);
    GTEST_LOG_(INFO) << "DeviceStatusMsdpClientImplTest end";
}
} // namespace
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
