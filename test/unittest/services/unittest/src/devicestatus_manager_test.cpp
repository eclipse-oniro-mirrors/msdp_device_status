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
} // namespace

void DeviceStatusManagerTest::SetUpTestCase()
{
    boomerangCallback_ = new (std::nothrow) BoomerangModuleTestCallback();
}

void DeviceStatusManagerTest::TearDownTestCase()
{
    delete boomerangCallback_;
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

namespace {
/**
 * @tc.name: HandlerPageScrollerEventTest
 * @tc.desc: test devicestatus callback in proxy
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusManagerTest, HandlerPageScrollerEventTest, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "HandlerPageScrollerEventTest start";
    deviceStatusManager->HandlerPageScrollerEvent();
    EXPECT_EQ(deviceStatusManager->g_deviceManager_, nullptr);
    deviceStatusManager->g_deviceManager_ = std::make_shared<DeviceStatusManager>();
    ASSERT_NE(deviceStatusManager->g_deviceManager_, nullptr);
    deviceStatusManager->g_deviceManager_->lastEnable_ = true;
    deviceStatusManager->HandlerPageScrollerEvent();
    deviceStatusManager->g_deviceManager_->lastEnable_ = false;
    deviceStatusManager->HandlerPageScrollerEvent();
    EXPECT_TRUE(deviceStatusManager->lastEnable_);
    GTEST_LOG_(INFO) << "HandlerPageScrollerEventTest end";
}

/**
 * @tc.name: OnSurfaceCaptureTest
 * @tc.desc: test devicestatus OnSurfaceCapture
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusManagerTest, OnSurfaceCaptureTest, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "OnSurfaceCaptureTest start";
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = nullptr;
    deviceStatusManager->OnSurfaceCapture(-1, pixelMap);

    int32_t windowId = 0;
    std::string bundleName;
    int32_t result = deviceStatusManager->GetFocuseWindowId(windowId, bundleName);
    EXPECT_EQ(result, RET_OK);

    pixelMap = CreateEmptyPixelMap();
    deviceStatusManager->OnSurfaceCapture(windowId, pixelMap);
    EXPECT_TRUE(deviceStatusManager->lastEnable_);

    auto algo = std::make_shared<BoomerangAlgoImpl>();
    EXPECT_NE(algo, nullptr);
    std::shared_ptr<OHOS::Media::PixelMap> encodePixelMap;
    EXPECT_EQ(encodePixelMap, nullptr);
    algo->EncodeImage(pixelMap, "metadata", encodePixelMap);
    EXPECT_NE(encodePixelMap, nullptr);
    deviceStatusManager->OnSurfaceCapture(windowId, pixelMap);
    EXPECT_TRUE(deviceStatusManager->lastEnable_);
    GTEST_LOG_(INFO) << "OnSurfaceCaptureTest end";
}

/**
 * @tc.name: BoomerangDecodeImageTest
 * @tc.desc: test devicestatus BoomerangDecodeImage
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusManagerTest, BoomerangDecodeImageTest, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "BoomerangDecodeImageTest start";
    std::shared_ptr<Media::PixelMap> pixelMap = nullptr;
    int32_t result = deviceStatusManager->BoomerangDecodeImage(pixelMap, boomerangCallback_);
    EXPECT_EQ(result, RET_ERR);

    sptr<IRemoteBoomerangCallback> callback = nullptr;
    result = deviceStatusManager->BoomerangDecodeImage(pixelMap, callback);
    EXPECT_EQ(result, RET_ERR);

    pixelMap = CreateEmptyPixelMap();
    result = deviceStatusManager->BoomerangDecodeImage(pixelMap, boomerangCallback_);
    EXPECT_EQ(result, RET_OK);
    GTEST_LOG_(INFO) << "BoomerangDecodeImageTest end";
}

/**
 * @tc.name: GetFocuseWindowIdEventTest
 * @tc.desc: test devicestatus GetFocuseWindowId
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusManagerTest, GetFocuseWindowIdEventTest, TestSize.Level0) {
    GTEST_LOG_(INFO) << "GetFocuseWindowIdEventTest start";
    int32_t windowId = 0;
    std::string bundleName;
    int32_t result = deviceStatusManager->GetFocuseWindowId(windowId, bundleName);
    EXPECT_EQ(result, RET_OK);
    GTEST_LOG_(INFO) << "GetFocuseWindowIdEventTest end";
}

/**
 * @tc.name: OnAddSystemAbilityTest
 * @tc.desc: test devicestatus OnAddSystemAbilityTest Test
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusManagerTest, OnAddSystemAbilityTest, TestSize.Level0) {
    GTEST_LOG_(INFO) << "OnAddSystemAbilityTest start";
    auto accessibilityStatusChange =
        new (std::nothrow) DeviceStatusManager::AccessibilityStatusChange();
    ASSERT_NE(accessibilityStatusChange, nullptr);
    std::string deviceId;
    deviceStatusManager->g_deviceManager_ = nullptr;
    accessibilityStatusChange->OnAddSystemAbility(RET_ERR, deviceId);
    EXPECT_EQ(deviceStatusManager->g_deviceManager_, nullptr);

    deviceStatusManager->g_deviceManager_ = std::make_shared<DeviceStatusManager>();
    accessibilityStatusChange->OnAddSystemAbility(ACCESSIBILITY_MANAGER_SERVICE_ID, deviceId);
    EXPECT_FALSE(deviceStatusManager->g_deviceManager_->isAccessibilityInit);

    accessibilityStatusChange->OnAddSystemAbility(WINDOW_MANAGER_SERVICE_ID, deviceId);
    EXPECT_NE(deviceStatusManager->g_deviceManager_, nullptr);
    GTEST_LOG_(INFO) << "OnAddSystemAbilityTest end";
}

/**
 * @tc.name: OnRemoveSystemAbilityTest
 * @tc.desc: test devicestatus OnRemoveSystemAbilityTest
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusManagerTest, OnRemoveSystemAbilityTest, TestSize.Level0) {
    GTEST_LOG_(INFO) << "OnRemoveSystemAbilityTest start";
    auto accessibilityStatusChange =
        new (std::nothrow) DeviceStatusManager::AccessibilityStatusChange();
    ASSERT_NE(accessibilityStatusChange, nullptr);
    std::string deviceId;
    accessibilityStatusChange->OnRemoveSystemAbility(ACCESSIBILITY_MANAGER_SERVICE_ID, deviceId);

    deviceStatusManager->g_deviceManager_ = std::make_shared<DeviceStatusManager>();
    accessibilityStatusChange->OnRemoveSystemAbility(WINDOW_MANAGER_SERVICE_ID, deviceId);
    EXPECT_NE(deviceStatusManager->g_deviceManager_, nullptr);

    accessibilityStatusChange->OnRemoveSystemAbility(WINDOW_MANAGER_SERVICE_ID, deviceId);
    EXPECT_TRUE(deviceStatusManager->lastEnable_);
    GTEST_LOG_(INFO) << "OnRemoveSystemAbilityTest end";
}

/**
 * @tc.name: OnWindowSystemBarPropertyChangedTest
 * @tc.desc: test devicestatus OnWindowSystemBarPropertyChanged
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusManagerTest, OnWindowSystemBarPropertyChangedTest, TestSize.Level0) {
    GTEST_LOG_(INFO) << "OnWindowSystemBarPropertyChangedTest start";
    auto listener = new (std::nothrow) DeviceStatusManager::SystemBarStyleChangedListener();
    EXPECT_NE(listener, nullptr);
    SystemBarProperty property4Params(true, 1, 1, true);
    listener->OnWindowSystemBarPropertyChanged({}, property4Params);
    EXPECT_NE(deviceStatusManager->g_deviceManager_, nullptr);
    EXPECT_EQ(deviceStatusManager->g_deviceManager_->lastEnable_, true);

    property4Params.enable_ = false;
    listener->OnWindowSystemBarPropertyChanged(WindowType::WINDOW_TYPE_STATUS_BAR, property4Params);
    EXPECT_EQ(deviceStatusManager->g_deviceManager_->lastEnable_, false);
    GTEST_LOG_(INFO) << "OnWindowSystemBarPropertyChangedTest end";
}

/**
 * @tc.name: BoomerangEncodeImageTest
 * @tc.desc: test devicestatus BoomerangEncodeImage
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusManagerTest, BoomerangEncodeImageTest, TestSize.Level0) {
    GTEST_LOG_(INFO) << "BoomerangEncodeImageTest start";
    std::shared_ptr<Media::PixelMap> pixelMap;
    int32_t result = deviceStatusManager->BoomerangEncodeImage(pixelMap, "metadata", boomerangCallback_);
    EXPECT_EQ(result, RET_ERR);

    sptr<IRemoteBoomerangCallback> nullCallback;
    result = deviceStatusManager->BoomerangEncodeImage(pixelMap, "metadata", nullCallback);
    EXPECT_EQ(result, RET_ERR);

    pixelMap = CreateEmptyPixelMap();
    result = deviceStatusManager->BoomerangEncodeImage(pixelMap, "metadata", boomerangCallback_);
    EXPECT_EQ(result, RET_OK);
    GTEST_LOG_(INFO) << "BoomerangEncodeImageTest end";
}

/**
 * @tc.name: SubmitMetadataTest
 * @tc.desc: test devicestatus SubmitMetadataTest
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusManagerTest, SubmitMetadataTest, TestSize.Level0) {
    GTEST_LOG_(INFO) << "SubmitMetadataTest start";
    deviceStatusManager->notityListener_ = nullptr;
    int32_t result = deviceStatusManager->SubmitMetadata("metadata");
    EXPECT_EQ(result, RET_ERR);

    deviceStatusManager->notityListener_ = boomerangCallback_;
    result = deviceStatusManager->SubmitMetadata("metadata");
    EXPECT_EQ(result, RET_OK);
    GTEST_LOG_(INFO) << "SubmitMetadataTest end";
}

/**
 * @tc.name: SubscribeTest
 * @tc.desc: test devicestatus SubscribeTest
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusManagerTest, SubscribeTest, TestSize.Level0) {
    GTEST_LOG_(INFO) << "SubscribeTest start";
    int32_t result = deviceStatusManager->Subscribe(BOOMERANG_TYPE_INVALID, "com.boomerang.test", boomerangCallback_);
    EXPECT_EQ(result, RET_ERR);

    result = deviceStatusManager->Subscribe(BOOMERANG_TYPE_BOOMERANG, "com.boomerang.test", nullptr);
    EXPECT_EQ(result, RET_ERR);

    result = deviceStatusManager->Subscribe(BOOMERANG_TYPE_BOOMERANG, "com.boomerang.test", boomerangCallback_);
    EXPECT_EQ(result, RET_OK);

    GTEST_LOG_(INFO) << "SubscribeTest end";
}

/**
 * @tc.name: NotifyMetadataTest
 * @tc.desc: test devicestatus NotifyMetadataTest
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusManagerTest, NotifyMetadataTest, TestSize.Level0) {
    GTEST_LOG_(INFO) << "NotifyMetadataTest start";
    int32_t result = deviceStatusManager->Subscribe(BOOMERANG_TYPE_BOOMERANG, "com.boomerang.test", boomerangCallback_);
    EXPECT_EQ(result, RET_OK);

    result = deviceStatusManager->NotifyMetadata("com.boomerang.test", nullptr);
    EXPECT_EQ(result, RET_ERR);

    result = deviceStatusManager->NotifyMetadata("com.boomerang.test", boomerangCallback_);
    EXPECT_EQ(result, RET_OK);

    result = deviceStatusManager->Unsubscribe(BOOMERANG_TYPE_BOOMERANG, "com.boomerang.test", boomerangCallback_);
    EXPECT_EQ(result, RET_OK);

    result = deviceStatusManager->NotifyMetadata("com.boomerang.test", boomerangCallback_);
    EXPECT_EQ(result, RET_ERR);
    GTEST_LOG_(INFO) << "NotifyMetadataTest end";
}

/**
 * @tc.name: BoomerangUnsubscribeTest
 * @tc.desc: test devicestatus BoomerangUnsubscribeTest
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusManagerTest, BoomerangUnsubscribeTest, TestSize.Level0) {
    GTEST_LOG_(INFO) << "BoomerangUnsubscribeTest start";
    int32_t result = deviceStatusManager->Unsubscribe(BOOMERANG_TYPE_INVALID, "com.boomerang.test", boomerangCallback_);
    EXPECT_EQ(result, RET_ERR);

    result = deviceStatusManager->Unsubscribe(BOOMERANG_TYPE_BOOMERANG, "com.boomerang.test", nullptr);
    EXPECT_EQ(result, RET_ERR);

    result = deviceStatusManager->Unsubscribe(BOOMERANG_TYPE_BOOMERANG, "com.boomerang.test", boomerangCallback_);
    EXPECT_EQ(result, RET_ERR);

    result = deviceStatusManager->Subscribe(BOOMERANG_TYPE_BOOMERANG, "com.boomerang.test", boomerangCallback_);
    EXPECT_EQ(result, RET_OK);

    result = deviceStatusManager->Unsubscribe(BOOMERANG_TYPE_BOOMERANG, "com.boomerang.test", boomerangCallback_);
    EXPECT_EQ(result, RET_OK);
    GTEST_LOG_(INFO) << "BoomerangUnsubscribeTest end";
}

/**
 * @tc.name: AccessibilityDisconnectTest
 * @tc.desc: test devicestatus AccessibilityDisconnectTest
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusManagerTest, AccessibilityDisconnectTest, TestSize.Level0) {
    GTEST_LOG_(INFO) << "AccessibilityDisconnectTest start";
    auto accessibleAbilityManager  = new (std::nothrow) AccessibilityManager();
    ASSERT_NE(accessibleAbilityManager, nullptr);
    AccessibilityCallback callback = [](int32_t type) {
        GTEST_LOG_(INFO) << "AccessibilityCallback called with type: " << type;
        EXPECT_EQ(type, ON_ABILITY_SCROLLED_EVENT);
    };
    accessibleAbilityManager->AccessibilityDisconnect();
    auto listener = std::make_shared<AccessibilityManager::AccessibleAbilityListenerImpl>(callback);
    ASSERT_NE(listener, nullptr);
    listener->OnAccessibilityEvent(Accessibility::EventType::TYPE_VIEW_SCROLLED_EVENT);
    EXPECT_NE(listener->callback_, nullptr);

    bool ret = listener->OnKeyPressEvent(nullptr);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "AccessibilityDisconnectTest end";
}
} // namespace
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
