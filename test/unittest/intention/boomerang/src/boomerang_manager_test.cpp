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

#include "accesstoken_kit.h"
#include <gmock/gmock.h>
#include "gtest/gtest.h"
#include "ipc_skeleton.h"

#include "boomerang_manager.h"
#include "boomerang_callback_stub.h"
#include "boomerang_server.h"
#include "devicestatus_callback_stub.h"
#include "devicestatus_define.h"
#include "devicestatus_dumper.h"
#include "devicestatus_manager.h"
#include "devicestatus_hisysevent.h"
#include "fi_log.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "parcel.h"

#undef LOG_TAG
#define LOG_TAG "BoomerangManagerTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
constexpr int32_t RET_IPC_ERR = 5;
inline constexpr size_t MAX_STRING_LEN{1024};
} // namespace

class BoomerangManagerTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
    class BoomerangManagerTestCallback : public BoomerangCallbackStub {
    public:
    explicit BoomerangManagerTestCallback() {}
    virtual ~BoomerangManagerTestCallback() {};
    MOCK_METHOD(void, OnScreenshotResult, (const BoomerangData& data), (override));
    MOCK_METHOD(void, OnNotifyMetadata, (const std::string& metadata), (override));
    MOCK_METHOD(void, OnEncodeImageResult, (std::shared_ptr<Media::PixelMap> pixelMap), (override));
    MOCK_METHOD(void, EmitOnEvent, (BoomerangData& data));
    MOCK_METHOD(void, EmitOnMetadata, (std::string metadata));
    MOCK_METHOD(void, EmitOnEncodeImage, (std::shared_ptr<Media::PixelMap> pixelMap));
    };
};

/**
 * @tc.name: BoomerangManagerTest001
 * @tc.desc: BoomerangManagerTest001 for check GetInstance
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(BoomerangManagerTest, BoomerangManagerTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BoomerangManagerTest001 start";
    string metadata = "test";
    ASSERT_NO_FATAL_FAILURE(BoomerangManager::GetInstance().SubmitMetadata(metadata));
    GTEST_LOG_(INFO) << "BoomerangManagerTest001 end";
}

/**
 * @tc.name: BoomerangManagerTest002
 * @tc.desc: BoomerangManagerTest002 for SubscribeCallback subCallback is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(BoomerangManagerTest, BoomerangManagerTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BoomerangManagerTest002 start";
    char bundleName[MAX_STRING_LEN] = {0};
    BoomerangType type { BOOMERANG_TYPE_BOOMERANG };
    sptr<IRemoteBoomerangCallback> subCallback { nullptr };
    BoomerangManager& boomerangManager = BoomerangManager::GetInstance();
    int32_t ret = boomerangManager.SubscribeCallback(type, bundleName, subCallback);
    EXPECT_EQ(ret, RET_IPC_ERR);
    GTEST_LOG_(INFO) << "BoomerangManagerTest002 end";
}

/**
 * @tc.name: BoomerangManagerTest003
 * @tc.desc: BoomerangManagerTest003 for SubscribeCallback
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(BoomerangManagerTest, BoomerangManagerTest003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BoomerangManagerTest003 start";
    char bundleName[MAX_STRING_LEN] = {0};
    BoomerangType type { BOOMERANG_TYPE_BOOMERANG };
    sptr<IRemoteBoomerangCallback> subCallback = new (std::nothrow) BoomerangManagerTestCallback();
    BoomerangManager& boomerangManager = BoomerangManager::GetInstance();
    int32_t ret = boomerangManager.SubscribeCallback(type, bundleName, subCallback);
    EXPECT_EQ(ret, RET_OK);
    GTEST_LOG_(INFO) << "BoomerangManagerTest003 end";
}

/**
 * @tc.name: BoomerangManagerTest004
 * @tc.desc: BoomerangManagerTest004 for UnsubscribeCallback subCallback is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(BoomerangManagerTest, BoomerangManagerTest004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BoomerangManagerTest004 start";
    BoomerangType type { BOOMERANG_TYPE_BOOMERANG };
    char bundleName[MAX_STRING_LEN] = {0};
    sptr<IRemoteBoomerangCallback> unsubCallback { nullptr };
    BoomerangManager& boomerangManager = BoomerangManager::GetInstance();
    int32_t ret = boomerangManager.UnsubscribeCallback(type, bundleName, unsubCallback);
    EXPECT_EQ(ret, RET_IPC_ERR);
    GTEST_LOG_(INFO) << "BoomerangManagerTest004 end";
}

/**
 * @tc.name: BoomerangManagerTest005
 * @tc.desc: BoomerangManagerTest005 for UnsubscribeCallback
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(BoomerangManagerTest, BoomerangManagerTest005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BoomerangManagerTest005 start";
    char bundleName[MAX_STRING_LEN] = {0};
    BoomerangType type { BOOMERANG_TYPE_BOOMERANG };
    sptr<IRemoteBoomerangCallback> unsubCallback = new (std::nothrow) BoomerangManagerTestCallback();
    BoomerangManager& boomerangManager = BoomerangManager::GetInstance();
    int32_t ret = boomerangManager.UnsubscribeCallback(type, bundleName, unsubCallback);
    EXPECT_EQ(ret, RET_OK);
    GTEST_LOG_(INFO) << "BoomerangManagerTest005 end";
}

/**
 * @tc.name: BoomerangManagerTest006
 * @tc.desc: BoomerangManagerTest006 for NotifyMetadataBindingEvent subCallback is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(BoomerangManagerTest, BoomerangManagerTest006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BoomerangManagerTest006 start";
    char bundleName[MAX_STRING_LEN] = {0};
    sptr<IRemoteBoomerangCallback> notifyCallback { nullptr };
    BoomerangManager& boomerangManager = BoomerangManager::GetInstance();
    int32_t ret = boomerangManager.NotifyMetadataBindingEvent(bundleName, notifyCallback);
    EXPECT_EQ(ret, RET_IPC_ERR);
    GTEST_LOG_(INFO) << "BoomerangManagerTest006 end";
}

/**
 * @tc.name: BoomerangManagerTest007
 * @tc.desc: BoomerangManagerTest007 for NotifyMetadataBindingEvent
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(BoomerangManagerTest, BoomerangManagerTest007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BoomerangManagerTest007 start";
    char bundleName[MAX_STRING_LEN] = {0};
    sptr<IRemoteBoomerangCallback> notifyCallback = new (std::nothrow) BoomerangManagerTestCallback();
    BoomerangManager& boomerangManager = BoomerangManager::GetInstance();
    int32_t ret = boomerangManager.NotifyMetadataBindingEvent(bundleName, notifyCallback);
    EXPECT_EQ(ret, RET_OK);
    GTEST_LOG_(INFO) << "BoomerangManagerTest007 end";
}

/**
 * @tc.name: BoomerangManagerTest008
 * @tc.desc: BoomerangManagerTest008 for encodeCallback is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(BoomerangManagerTest, BoomerangManagerTest008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BoomerangManagerTest008 start";
    string metadata = "test";
    sptr<IRemoteBoomerangCallback> encodeCallback = nullptr;
    Media::InitializationOptions initOptions;
    initOptions.size = {1080, 1920};
    initOptions.pixelFormat = Media::PixelFormat::BGRA_8888;
    initOptions.editable = true;
    std::shared_ptr<Media::PixelMap> pixelMap = Media::PixelMap::Create(initOptions);
    BoomerangManager& boomerangManager = BoomerangManager::GetInstance();
    int32_t ret = boomerangManager.BoomerangEncodeImage(pixelMap, metadata, encodeCallback);
    EXPECT_EQ(ret, RET_IPC_ERR);
    GTEST_LOG_(INFO) << "BoomerangManagerTest008 end";
}

/**
 * @tc.name: BoomerangManagerTest009
 * @tc.desc: BoomerangManagerTest009 for pixelMap is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(BoomerangManagerTest, BoomerangManagerTest009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BoomerangManagerTest009 start";
    string metadata = "test";
    sptr<IRemoteBoomerangCallback> encodeCallback = new (std::nothrow) BoomerangManagerTestCallback();
    std::shared_ptr<Media::PixelMap> pixelMap { nullptr };
    BoomerangManager& boomerangManager = BoomerangManager::GetInstance();
    int32_t ret = boomerangManager.BoomerangEncodeImage(pixelMap, metadata, encodeCallback);
    EXPECT_EQ(ret, RET_IPC_ERR);
    GTEST_LOG_(INFO) << "BoomerangManagerTest009 end";
}

/**
 * @tc.name: BoomerangManagerTest010
 * @tc.desc: BoomerangManagerTest010 for pixelMap and encodeCallback is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(BoomerangManagerTest, BoomerangManagerTest010, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BoomerangManagerTest010 start";
    string metadata = "test";
    sptr<IRemoteBoomerangCallback> encodeCallback = nullptr;
    std::shared_ptr<Media::PixelMap> pixelMap { nullptr };
    BoomerangManager& boomerangManager = BoomerangManager::GetInstance();
    int32_t ret = boomerangManager.BoomerangEncodeImage(pixelMap, metadata, encodeCallback);
    EXPECT_EQ(ret, RET_IPC_ERR);
    GTEST_LOG_(INFO) << "BoomerangManagerTest010 end";
}

/**
 * @tc.name: BoomerangManagerTest011
 * @tc.desc: BoomerangManagerTest011 for BoomerangEncodeImage
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(BoomerangManagerTest, BoomerangManagerTest011, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BoomerangManagerTest011 start";
    string metadata = "test";
    sptr<IRemoteBoomerangCallback> encodeCallback = new (std::nothrow) BoomerangManagerTestCallback();
    Media::InitializationOptions initOptions;
    initOptions.size = {1080, 1920};
    initOptions.pixelFormat = Media::PixelFormat::BGRA_8888;
    initOptions.editable = true;
    std::shared_ptr<Media::PixelMap> pixelMap = Media::PixelMap::Create(initOptions);
    BoomerangManager& boomerangManager = BoomerangManager::GetInstance();
    int32_t ret = boomerangManager.BoomerangEncodeImage(pixelMap, metadata, encodeCallback);
    EXPECT_EQ(ret, RET_OK);
    GTEST_LOG_(INFO) << "BoomerangManagerTest011 end";
}

/**
 * @tc.name: BoomerangManagerTest012
 * @tc.desc: BoomerangManagerTest012 for SubmitMetadata
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangManagerTest, BoomerangManagerTest012, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BoomerangManagerTest012 start";
    string metadata = "";
    BoomerangManager& boomerangManager = BoomerangManager::GetInstance();
    int32_t ret = boomerangManager.SubmitMetadata(metadata);
    EXPECT_EQ(ret, RET_OK);
    GTEST_LOG_(INFO) << "BoomerangManagerTest012 end";
}

/**
 * @tc.name: BoomerangManagerTest013
 * @tc.desc: BoomerangManagerTest013 for SubmitMetadata
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BoomerangManagerTest, BoomerangManagerTest013, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BoomerangManagerTest013 start";
    string metadata = "test";
    BoomerangManager& boomerangManager = BoomerangManager::GetInstance();
    int32_t ret = boomerangManager.SubmitMetadata(metadata);
    EXPECT_EQ(ret, RET_ERR);
    GTEST_LOG_(INFO) << "BoomerangManagerTest013 end";
}

/**
 * @tc.name: BoomerangManagerTest014
 * @tc.desc: BoomerangManagerTest014 for decodeCallback is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(BoomerangManagerTest, BoomerangManagerTest014, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BoomerangManagerTest014 start";
    sptr<IRemoteBoomerangCallback> decodeCallback { nullptr };
    Media::InitializationOptions initOptions;
    initOptions.size = {1080, 1920};
    initOptions.pixelFormat = Media::PixelFormat::BGRA_8888;
    initOptions.editable = true;
    std::shared_ptr<Media::PixelMap> pixelMap = Media::PixelMap::Create(initOptions);
    BoomerangManager& boomerangManager = BoomerangManager::GetInstance();
    int32_t ret = boomerangManager.BoomerangDecodeImage(pixelMap, decodeCallback);
    EXPECT_EQ(ret, RET_IPC_ERR);
    GTEST_LOG_(INFO) << "BoomerangManagerTest014 end";
}

/**
 * @tc.name: BoomerangManagerTest015
 * @tc.desc: BoomerangManagerTest015 for pixelMap is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(BoomerangManagerTest, BoomerangManagerTest015, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BoomerangManagerTest015 start";
    sptr<IRemoteBoomerangCallback> decodeCallback = new (std::nothrow) BoomerangManagerTestCallback();
    std::shared_ptr<Media::PixelMap> pixelMap { nullptr };
    BoomerangManager& boomerangManager = BoomerangManager::GetInstance();
    int32_t ret = boomerangManager.BoomerangDecodeImage(pixelMap, decodeCallback);
    EXPECT_EQ(ret, RET_IPC_ERR);
    GTEST_LOG_(INFO) << "BoomerangManagerTest015 end";
}

/**
 * @tc.name: BoomerangManagerTest016
 * @tc.desc: BoomerangManagerTest016 for pixelMap and decodeCallback is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(BoomerangManagerTest, BoomerangManagerTest016, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BoomerangManagerTest016 start";
    sptr<IRemoteBoomerangCallback> decodeCallback { nullptr };
    std::shared_ptr<Media::PixelMap> pixelMap { nullptr };
    BoomerangManager& boomerangManager = BoomerangManager::GetInstance();
    int32_t ret = boomerangManager.BoomerangDecodeImage(pixelMap, decodeCallback);
    EXPECT_EQ(ret, RET_IPC_ERR);
    GTEST_LOG_(INFO) << "BoomerangManagerTest016 end";
}

/**
 * @tc.name: BoomerangManagerTest017
 * @tc.desc: BoomerangManagerTest017 for BoomerangDecodeImage
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(BoomerangManagerTest, BoomerangManagerTest017, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BoomerangManagerTest017 start";
    sptr<IRemoteBoomerangCallback> decodeCallback = new (std::nothrow) BoomerangManagerTestCallback();
    Media::InitializationOptions initOptions;
    initOptions.size = {1080, 1920};
    initOptions.pixelFormat = Media::PixelFormat::BGRA_8888;
    initOptions.editable = true;
    std::shared_ptr<Media::PixelMap> pixelMap = Media::PixelMap::Create(initOptions);
    BoomerangManager& boomerangManager = BoomerangManager::GetInstance();
    int32_t ret = boomerangManager.BoomerangDecodeImage(pixelMap, decodeCallback);
    EXPECT_EQ(ret, RET_OK);
    GTEST_LOG_(INFO) << "BoomerangManagerTest017 end";
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS