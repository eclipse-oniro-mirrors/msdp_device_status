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

#include "devicestatus_manager_test.h"

#include <chrono>
#include <iostream>
#include <thread>

#include <if_system_ability_manager.h>
#include <ipc_skeleton.h>
#include <securec.h>

#include "accessibility_manager.h"
#include "boomerang_data.h"
#include "devicestatus_define.h"
#include "devicestatus_manager.h"
#include "devicestatus_napi_manager.h"
#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "DeviceStatusManagerTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
    auto deviceStatusManager = std::make_shared<DeviceStatusManager>();
    static std::unique_ptr<Media::PixelMap> CreateEmptyPixelMap()
    {
        Media::InitializationOptions initOptions;
        initOptions.size = {1080, 1920};
        initOptions.pixelFormat = Media::PixelFormat::BGRA_8888;
        initOptions.editable = true;
        std::unique_ptr<Media::PixelMap> pixmap = Media::PixelMap::Create(initOptions);
        return pixmap;
    }
#ifdef BOOMERANG_ONESTEP
    const int32_t SYSTEM_BAR_HIDDEN = 0;
#endif
} // namespace

void DeviceStatusManagerTest::SetUpTestCase()
{
    boomerangCallback_ = new (std::nothrow) BoomerangModuleTestCallback();
    stationaryCallback_ = new (std::nothrow) StationaryModuleTestCallback();
}

void DeviceStatusManagerTest::TearDownTestCase()
{
    delete boomerangCallback_;
    delete stationaryCallback_;
}

void DeviceStatusManagerTest::SetUp() {}

void DeviceStatusManagerTest::TearDown() {}

void DeviceStatusManagerTest::BoomerangModuleTestCallback::OnScreenshotResult(const BoomerangData& screentshotData)
{
    GTEST_LOG_(INFO) << "OnScreenshotResult status: " << screentshotData.status;
    EXPECT_TRUE(screentshotData.status == BOOMERANG_STATUS_SCREEN_SHOT);
}

void DeviceStatusManagerTest::BoomerangModuleTestCallback::OnNotifyMetadata(const std::string& metadata)
{
    GTEST_LOG_(INFO) << "OnNotifyMetadata: " << metadata;
}

void DeviceStatusManagerTest::BoomerangModuleTestCallback::OnEncodeImageResult
    (std::shared_ptr<Media::PixelMap> pixelMap)
{
    EXPECT_NE(pixelMap, nullptr);
}

void DeviceStatusManagerTest::StationaryModuleTestCallback::OnDeviceStatusChanged(const
    Data& devicestatusData)
{
    GTEST_LOG_(INFO) << "StationaryModuleTestCallback type: " << devicestatusData.type;
    GTEST_LOG_(INFO) << "StationaryModuleTestCallback value: " << devicestatusData.value;
    EXPECT_TRUE(devicestatusData.type == Type::TYPE_VERTICAL_POSITION &&
        devicestatusData.value >= OnChangedValue::VALUE_INVALID &&
        devicestatusData.value <= OnChangedValue::VALUE_EXIT) << "StationaryModuleTestCallback failed";
}

namespace {
/**
 * @tc.name: HandlerPageScrollerEventTest
 * @tc.desc: test devicestatus callback in proxy
 * @tc.type: FUNC
 */
#ifdef BOOMERANG_ONESTEP
HWTEST_F(DeviceStatusManagerTest, HandlerPageScrollerEventTest, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "HandlerPageScrollerEventTest start";
    deviceStatusManager->HandlerPageScrollerEvent(SYSTEM_BAR_HIDDEN);
    EXPECT_EQ(deviceStatusManager->g_deviceManager_, nullptr);
    deviceStatusManager->g_deviceManager_ = std::make_shared<DeviceStatusManager>();
    ASSERT_NE(deviceStatusManager->g_deviceManager_, nullptr);
    deviceStatusManager->g_deviceManager_->lastEnable_ = true;
    deviceStatusManager->HandlerPageScrollerEvent(SYSTEM_BAR_HIDDEN);
    deviceStatusManager->g_deviceManager_->lastEnable_ = false;
    deviceStatusManager->HandlerPageScrollerEvent(SYSTEM_BAR_HIDDEN);
    EXPECT_TRUE(deviceStatusManager->lastEnable_);
    GTEST_LOG_(INFO) << "HandlerPageScrollerEventTest end";
}
#endif
} // namespace
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
