/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#define private public
#include "devicestatus_data_parse.h"
#include "devicestatus_msdp_mock.h"
#undef private
#include "devicestatus_msdp_interface.h"
#include "devicestatus_msdp_mock.h"
#include "devicestatus_msdp_client_impl.h"
#include "sensor_data_callback.h"

#undef LOG_TAG
#define LOG_TAG "DeviceStatusMocKTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
std::shared_ptr<DeviceStatusMsdpMock> g_testMock;
constexpr int32_t INVAILD_TIMER_INTERVAL { -1 };
constexpr int32_t ERR_INVALID_FD { -1 };
constexpr int32_t ZERO_TIMER_INTERVAL { 0 };
constexpr int32_t TIMER_INTERVAL { 3 };
#ifdef __aarch64__
const std::string DEVICESTATUS_MOCK_LIB_PATH { "/system/lib64/libdevicestatus_mock.z.so" };
#else
const std::string DEVICESTATUS_MOCK_LIB_PATH { "/system/lib/libdevicestatus_mock.z.so" };
#endif
} // namespace

class DeviceStatusMocKTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    int32_t LoadMockLibrary(const std::shared_ptr<MsdpAlgoHandle> &mockHandler);
    int32_t UnloadMockLibrary(const std::shared_ptr<MsdpAlgoHandle> &mockHandler);
protected:
    DeviceStatusMsdpMock deviceStatusMsdpMock;
};

void DeviceStatusMocKTest::SetUpTestCase()
{
    g_testMock = std::make_shared<DeviceStatusMsdpMock>();
}

void DeviceStatusMocKTest::TearDownTestCase()
{
    g_testMock = nullptr;
}

void DeviceStatusMocKTest::SetUp() {}

void DeviceStatusMocKTest::TearDown() {}

int32_t DeviceStatusMocKTest::LoadMockLibrary(const std::shared_ptr<MsdpAlgoHandle> &mockHandler)
{
    FI_HILOGI("Enter");
    if (mockHandler == nullptr) {
        FI_HILOGE("mockHandler is nullptr");
        return RET_ERR;
    }
    if (mockHandler->handle != nullptr) {
        FI_HILOGE("handle has exists");
        return RET_OK;
    }

    std::string dlName = DEVICESTATUS_MOCK_LIB_PATH;
    char libRealPath[PATH_MAX] = { 0 };
    if (realpath(dlName.c_str(), libRealPath) == nullptr) {
        FI_HILOGE("Get absolute algoPath is error, errno:%{public}d", errno);
        return RET_ERR;
    }

    mockHandler->handle = dlopen(libRealPath, RTLD_LAZY);
    if (mockHandler->handle == nullptr) {
        FI_HILOGE("Cannot load library error:%{public}s", dlerror());
        return RET_ERR;
    }

    mockHandler->create = reinterpret_cast<IMsdp* (*)()>(dlsym(mockHandler->handle, "Create"));
    mockHandler->destroy = reinterpret_cast<void *(*)(IMsdp*)>(dlsym(mockHandler->handle, "Destroy"));
    if (mockHandler->create == nullptr || mockHandler->destroy == nullptr) {
        FI_HILOGE("%{public}s dlsym create or destroy failed", dlName.c_str());
        dlclose(mockHandler->handle);
        mockHandler->Clear();
        return RET_ERR;
    }
    return RET_OK;
}

int32_t DeviceStatusMocKTest::UnloadMockLibrary(const std::shared_ptr<MsdpAlgoHandle> &mockHandler)
{
    FI_HILOGI("Enter");
    if (mockHandler == nullptr) {
        FI_HILOGE("mockHandler is nullptr");
        return RET_ERR;
    }
    if (mockHandler->handle == nullptr) {
        FI_HILOGE("handle is nullptr");
        return RET_ERR;
    }

    if (mockHandler->pAlgorithm != nullptr) {
        mockHandler->destroy(mockHandler->pAlgorithm);
        mockHandler->pAlgorithm = nullptr;
    }
    dlclose(mockHandler->handle);
    mockHandler->Clear();
    return RET_OK;
}

/**
 * @tc.name: DeviceStatusMocKTest001
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMocKTest, DeviceStatusMocKTest001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(g_testMock->Init());
    auto callback = std::make_shared<DeviceStatusMsdpClientImpl>();
    EXPECT_TRUE(g_testMock->RegisterCallback(callback) == ERR_OK);
    EXPECT_TRUE(g_testMock->UnregisterCallback() == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMocKTest002
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMocKTest, DeviceStatusMocKTest002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(g_testMock->Init());
    auto callback = std::make_shared<DeviceStatusMsdpClientImpl>();
    EXPECT_TRUE(g_testMock->RegisterCallback(callback) == ERR_OK);
    EXPECT_TRUE(g_testMock->Enable(Type::TYPE_INVALID) == ERR_OK);
    EXPECT_TRUE(g_testMock->Disable(Type::TYPE_INVALID) == ERR_OK);
    EXPECT_TRUE(g_testMock->UnregisterCallback() == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMocKTest003
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMocKTest, DeviceStatusMocKTest003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(g_testMock->Init());
    auto callback = std::make_shared<DeviceStatusMsdpClientImpl>();
    EXPECT_TRUE(g_testMock->RegisterCallback(callback) == ERR_OK);
    EXPECT_TRUE(g_testMock->Enable(Type::TYPE_ABSOLUTE_STILL) == ERR_OK);
    EXPECT_TRUE(g_testMock->Disable(Type::TYPE_ABSOLUTE_STILL) == ERR_OK);
    EXPECT_TRUE(g_testMock->UnregisterCallback() == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMocKTest004
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMocKTest, DeviceStatusMocKTest004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(g_testMock->Init());
    auto callback = std::make_shared<DeviceStatusMsdpClientImpl>();
    EXPECT_TRUE(g_testMock->RegisterCallback(callback) == ERR_OK);
    EXPECT_TRUE(g_testMock->Enable(Type::TYPE_HORIZONTAL_POSITION) == ERR_OK);
    EXPECT_TRUE(g_testMock->Disable(Type::TYPE_HORIZONTAL_POSITION) == ERR_OK);
    EXPECT_TRUE(g_testMock->UnregisterCallback() == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMocKTest005
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMocKTest, DeviceStatusMocKTest005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(g_testMock->Init());
    auto callback = std::make_shared<DeviceStatusMsdpClientImpl>();
    EXPECT_TRUE(g_testMock->RegisterCallback(callback) == ERR_OK);
    EXPECT_TRUE(g_testMock->Enable(Type::TYPE_VERTICAL_POSITION) == ERR_OK);
    EXPECT_TRUE(g_testMock->Disable(Type::TYPE_VERTICAL_POSITION) == ERR_OK);
    EXPECT_TRUE(g_testMock->UnregisterCallback() == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMocKTest006
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMocKTest, DeviceStatusMocKTest006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(g_testMock->Init());
    auto callback = std::make_shared<DeviceStatusMsdpClientImpl>();
    EXPECT_TRUE(g_testMock->RegisterCallback(callback) == ERR_OK);
    EXPECT_TRUE(g_testMock->Enable(Type::TYPE_LID_OPEN) == ERR_OK);
    EXPECT_TRUE(g_testMock->Disable(Type::TYPE_LID_OPEN) == ERR_OK);
    EXPECT_TRUE(g_testMock->UnregisterCallback() == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMocKTest007
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMocKTest, DeviceStatusMocKTest007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(g_testMock->Init());
    auto callback = std::make_shared<DeviceStatusMsdpClientImpl>();
    EXPECT_TRUE(g_testMock->RegisterCallback(callback) == ERR_OK);
    EXPECT_TRUE(g_testMock->Enable(Type::TYPE_MAX) == ERR_OK);
    EXPECT_TRUE(g_testMock->Disable(Type::TYPE_MAX) == ERR_OK);
    EXPECT_TRUE(g_testMock->UnregisterCallback() == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMocKTest008
 * @tc.desc: test devicestatus DisableCount
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMocKTest, DeviceStatusMocKTest008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(g_testMock->Init());
    auto callback = std::make_shared<DeviceStatusMsdpClientImpl>();
    EXPECT_TRUE(g_testMock->RegisterCallback(callback) == ERR_OK);
    EXPECT_TRUE(g_testMock->Enable(Type::TYPE_HORIZONTAL_POSITION) == ERR_OK);
    EXPECT_TRUE(g_testMock->Disable(Type::TYPE_HORIZONTAL_POSITION) == ERR_OK);
    EXPECT_TRUE(g_testMock->UnregisterCallback() == ERR_OK);
    EXPECT_TRUE(g_testMock->DisableCount(Type::TYPE_HORIZONTAL_POSITION) == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMocKTest009
 * @tc.desc: test devicestatus NotifyMsdpImpl
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMocKTest, DeviceStatusMocKTest009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_FALSE(g_testMock->NotifyMsdpImpl({}) == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMocKTest010
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMocKTest, DeviceStatusMocKTest010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_testMock->InitTimer();
    g_testMock->StartThread();
    std::make_unique<std::thread>(&DeviceStatusMsdpMock::LoopingThreadEntry, g_testMock)->detach();
    int32_t ret = g_testMock->SetTimerInterval(TIMER_INTERVAL);
    g_testMock->CloseTimer();
    EXPECT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMocKTest011
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMocKTest, DeviceStatusMocKTest011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_testMock->InitTimer();
    g_testMock->StartThread();
    std::make_unique<std::thread>(&DeviceStatusMsdpMock::LoopingThreadEntry, g_testMock)->detach();
    int32_t ret = g_testMock->SetTimerInterval(INVAILD_TIMER_INTERVAL);
    g_testMock->CloseTimer();
    EXPECT_TRUE(ret == RET_ERR);
}

/**
 * @tc.name: DeviceStatusMocKTest012
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMocKTest, DeviceStatusMocKTest012, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_testMock->InitTimer();
    g_testMock->StartThread();
    std::make_unique<std::thread>(&DeviceStatusMsdpMock::LoopingThreadEntry, g_testMock)->detach();
    int32_t ret = g_testMock->SetTimerInterval(ZERO_TIMER_INTERVAL);
    g_testMock->CloseTimer();
    EXPECT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMocKTest013
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMocKTest, DeviceStatusMocKTest013, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_testMock->InitTimer();
    g_testMock->StartThread();
    std::make_unique<std::thread>(&DeviceStatusMsdpMock::LoopingThreadEntry, g_testMock)->detach();
    int32_t ret = g_testMock->SetTimerInterval(ZERO_TIMER_INTERVAL);
    EXPECT_TRUE(ret == ERR_OK);
    g_testMock->TimerCallback();
    ret = g_testMock->GetDeviceStatusData();
    g_testMock->CloseTimer();
    EXPECT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMocKTest014
 * @tc.desc: test devicestatus NotifyMsdpImpl
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMocKTest, DeviceStatusMocKTest014, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_testMock->GetCallbackImpl() = nullptr;
    EXPECT_FALSE(g_testMock->NotifyMsdpImpl({}) == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMocKTest015
 * @tc.desc: test devicestatus NotifyMsdpImpl
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMocKTest, DeviceStatusMocKTest015, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto callback = std::make_shared<DeviceStatusMsdpClientImpl>();
    EXPECT_TRUE(g_testMock->RegisterCallback(callback) == ERR_OK);
    EXPECT_FALSE(g_testMock->NotifyMsdpImpl({TYPE_INVALID, VALUE_INVALID}) == ERR_OK);
}

/**
 * @tc.name: DeviceStatusMocKTest016
 * @tc.desc: test devicestatus NotifyMsdpImpl
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMocKTest, DeviceStatusMocKTest016, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_testMock->dataParse_ = nullptr;
    int32_t ret = g_testMock->GetDeviceStatusData();
    EXPECT_TRUE(ret == RET_ERR);
}

/**
 * @tc.name: DeviceStatusMocKTest017
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMocKTest, DeviceStatusMocKTest017, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = g_testMock->SetTimerInterval(ZERO_TIMER_INTERVAL);
    EXPECT_TRUE(ret == RET_ERR);
}

/**
 * @tc.name: DeviceStatusMocKTest018
 * @tc.desc: test devicestatus RegisterCallback
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMocKTest, DeviceStatusMocKTest018, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MsdpAlgoHandle> mock = std::make_shared<MsdpAlgoHandle>();
    int32_t ret = LoadMockLibrary(mock);
    ASSERT_EQ(ret, RET_OK);
    ASSERT_NE(mock->handle, nullptr);
    mock->pAlgorithm = mock->create();

    std::shared_ptr<DeviceStatusMsdpClientImpl> callback = std::make_shared<DeviceStatusMsdpClientImpl>();
    EXPECT_TRUE(mock->pAlgorithm->RegisterCallback(callback) == ERR_OK);
    EXPECT_TRUE(mock->pAlgorithm->UnregisterCallback() == ERR_OK);

    ret = UnloadMockLibrary(mock);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DeviceStatusMocKTest019
 * @tc.desc: test devicestatus Mock in Algorithm
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMocKTest, DeviceStatusMocKTest019, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_testMock->TimerCallback();
    FI_HILOGI("Test the abnormal branch.");
    int32_t ret = g_testMock->SetTimerInterval(ZERO_TIMER_INTERVAL);
    g_testMock->CloseTimer();
    EXPECT_TRUE(ret == RET_ERR);
}

/**
 * @tc.name: DeviceStatusMocKTest020
 * @tc.desc: first test devicestatus Mock in Disable
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMocKTest, DeviceStatusMocKTest020, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = deviceStatusMsdpMock.Disable(Type::TYPE_MAX);
    EXPECT_TRUE(ret == RET_OK);
}

/**
 * @tc.name: DeviceStatusMocKTest021
 * @tc.desc: second test devicestatus Mock in Disable
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMocKTest, DeviceStatusMocKTest021, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    deviceStatusMsdpMock.InitTimer();
    deviceStatusMsdpMock.StartThread();
    std::make_unique<std::thread>(&DeviceStatusMsdpMock::LoopingThreadEntry, g_testMock)->detach();
    int32_t ret = deviceStatusMsdpMock.Disable(Type::TYPE_MAX);
    EXPECT_TRUE(ret == RET_OK);
}

/**
 * @tc.name: DeviceStatusMocKTest022
 * @tc.desc: test devicestatus Mock in GetDeviceStatusData
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMocKTest, DeviceStatusMocKTest022, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    deviceStatusMsdpMock.dataParse_ = std::make_unique<DeviceStatusDataParse>();
    int32_t ret = deviceStatusMsdpMock.GetDeviceStatusData();
    EXPECT_TRUE(ret == RET_OK);
}

/**
 * @tc.name: DeviceStatusMocKTest023
 * @tc.desc: first test devicestatus Mock in SetTimerInterval
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMocKTest, DeviceStatusMocKTest023, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    deviceStatusMsdpMock.timerFd_ = ERR_INVALID_FD;
    int32_t ret = deviceStatusMsdpMock.SetTimerInterval(INVAILD_TIMER_INTERVAL);
    EXPECT_TRUE(ret == RET_ERR);
}

/**
 * @tc.name: DeviceStatusMocKTest024
 * @tc.desc: second test devicestatus Mock in SetTimerInterval
 * @tc.type: FUNC
 */
HWTEST_F(DeviceStatusMocKTest, DeviceStatusMocKTest024, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    deviceStatusMsdpMock.InitTimer();
    deviceStatusMsdpMock.StartThread();
    std::make_unique<std::thread>(&DeviceStatusMsdpMock::LoopingThreadEntry, g_testMock)->detach();
    int32_t ret = deviceStatusMsdpMock.SetTimerInterval(INVAILD_TIMER_INTERVAL);
    deviceStatusMsdpMock.CloseTimer();
    EXPECT_TRUE(ret == RET_ERR);
    EXPECT_TRUE(deviceStatusMsdpMock.timerFd_ == ERR_INVALID_FD);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
