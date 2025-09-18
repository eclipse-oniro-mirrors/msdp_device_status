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
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS