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

#include <memory>
#include <vector>

#include <unistd.h>

#include "accesstoken_kit.h"
#include "device_manager.h"
#include "dm_device_info.h"
#include <gtest/gtest.h>
#include "nativetoken_kit.h"
#include "securec.h"
#include "token_setproc.h"

#include "devicestatus_define.h"
#include "devicestatus_errors.h"
#include "dsoftbus_adapter_impl.h"
#include "dsoftbus_adapter.h"
#include "utility.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <thread>

#undef LOG_TAG
#define LOG_TAG "DsoftbusAdapterTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
const std::string SYSTEM_CORE { "system_core" };
const std::string SYSTEM_BASIC { "system_basic" };
uint64_t g_tokenID { 0 };
#define SERVER_SESSION_NAME "ohos.msdp.device_status.intention.serversession"
#define DSTB_HARDWARE DistributedHardware::DeviceManager::GetInstance()
const std::string PKG_NAME_PREFIX { "DBinderBus_Dms_" };
const std::string CLIENT_SESSION_NAME { "ohos.msdp.device_status.intention.clientsession." };
[[maybe_unused]] constexpr size_t DEVICE_NAME_SIZE_MAX { 256 };
[[maybe_unused]] constexpr size_t PKG_NAME_SIZE_MAX { 65 };
[[maybe_unused]] constexpr int32_t SOCKET_SERVER { 0 };
[[maybe_unused]] constexpr int32_t SOCKET_CLIENT { 1 };
constexpr int32_t TEST_SOCKET { 1 };
const char* g_cores[] = { "ohos.permission.INPUT_MONITORING" };
} // namespace

class DsoftbusAdapterTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase();
    static void SetPermission(const std::string &level, const char** perms, size_t permAmount);
    static void RemovePermission();
    static std::string GetLocalNetworkId();
    
private:
    std::shared_ptr<DSoftbusAdapterImpl> adapter_;
};

void DsoftbusAdapterTest::SetPermission(const std::string &level, const char** perms, size_t permAmount)
{
    CALL_DEBUG_ENTER;
    if (perms == nullptr || permAmount == 0) {
        FI_HILOGE("The perms is empty");
        return;
    }

    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = permAmount,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "DsoftbusAdapterTest",
        .aplStr = level.c_str(),
    };
    g_tokenID = GetAccessTokenId(&infoInstance);
    if (g_tokenID == 0) {
    FI_HILOGE("Failed to get access token id");
    return;
    }
}

void DsoftbusAdapterTest::RemovePermission()
{
    CALL_DEBUG_ENTER;
    int32_t ret = OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenID);
    if (ret != RET_OK) {
        FI_HILOGE("Failed to remove permission");
        return;
    }
}

void DsoftbusAdapterTest::SetUpTestCase() {}

void DsoftbusAdapterTest::SetUp()
{
    adapter_ = DSoftbusAdapterImpl::GetInstance();
    ASSERT_NE(nullptr, adapter_.get()) << "Failed to get adapter instance";
}

void DsoftbusAdapterTest::TearDown()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

class DSoftbusObserver final : public IDSoftbusObserver {
public:
    DSoftbusObserver() = default;
    ~DSoftbusObserver() = default;

    void OnBind(const std::string &networkId) {}
    void OnShutdown(const std::string &networkId) {}
    void OnConnected(const std::string &networkId) {}
    bool OnPacket(const std::string &networkId, NetPacket &packet)
    {
        return true;
    }
    bool OnRawData(const std::string &networkId, const void *data, uint32_t dataLen)
    {
        return true;
    }
};

std::string DsoftbusAdapterTest::GetLocalNetworkId()
{
    auto packageName = PKG_NAME_PREFIX + std::to_string(getpid());
    OHOS::DistributedHardware::DmDeviceInfo dmDeviceInfo;
    if (int32_t errCode = DSTB_HARDWARE.GetLocalDeviceInfo(packageName, dmDeviceInfo); errCode != RET_OK) {
        FI_HILOGE("GetLocalBasicInfo failed, errCode:%{public}d", errCode);
        return {};
    }
    FI_HILOGD("LocalNetworkId:%{public}s", Utility::Anonymize(dmDeviceInfo.networkId).c_str());
    return dmDeviceInfo.networkId;
}

/**
 * @tc.name: TestOnBindLink
 * @tc.desc: Test OnBindLink
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, OnBindLink, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_BASIC, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    auto adapter = DSoftbusAdapterImpl::GetInstance();
    PeerSocketInfo info;
    char deviceId[] = "test_device_for_callback";
    info.networkId = deviceId;
    ASSERT_NO_FATAL_FAILURE(adapter->OnBind(TEST_SOCKET, info));
    EXPECT_TRUE(adapter->HasSessionExisted(deviceId));
    RemovePermission();
}

/**
 * @tc.name: TestOnShutdownLink
 * @tc.desc: Test OnShutdownLink
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, OnShutdownLink, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_BASIC, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    auto adapter = DSoftbusAdapterImpl::GetInstance();
    PeerSocketInfo info;
    char deviceId[] = "shutdown_test_device";
    info.networkId = deviceId;
    ASSERT_NO_FATAL_FAILURE(adapter->OnBind(100, info));
    EXPECT_TRUE(adapter->HasSessionExisted(deviceId));
    ASSERT_NO_FATAL_FAILURE(adapter->OnShutdown(100, SHUTDOWN_REASON_UNKNOWN));
    EXPECT_FALSE(adapter->HasSessionExisted(deviceId));
    RemovePermission();
}
/**
 * @tc.name: TestOnBytesAvailable
 * @tc.desc: Test OnBytesAvailable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, OnBytesAvailable, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    auto adapter = DSoftbusAdapterImpl::GetInstance();
    PeerSocketInfo info;
    char deviceId[] = "bytes_test_device";
    info.networkId = deviceId;
    ASSERT_NO_FATAL_FAILURE(adapter->OnBind(200, info));
    uint32_t normalData[2] = {static_cast<uint32_t>(MessageId::DSOFTBUS_START_COOPERATE), 0};
    ASSERT_NO_FATAL_FAILURE(adapter->OnBytes(200, normalData, sizeof(normalData)));
    std::string rawData = "Raw data test";
    ASSERT_NO_FATAL_FAILURE(adapter->OnBytes(200, rawData.c_str(), rawData.size()));
    RemovePermission();
}

/**
 * @tc.name: TestCheckDeviceOsType
 * @tc.desc: Test CheckDeviceOsType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, CheckDeviceOsType, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    std::string networkId = "test_device_os_type";
    bool result = adapter_->CheckDeviceOsType(networkId);
    EXPECT_FALSE(result);
    RemovePermission();
}

/**
 * @tc.name: TestConfigTcpAlivekeepAliveCount
 * @tc.desc: Test ConfigTcpAlive_keepAliveCount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, ConfigTcpAliveKeepAliveCount, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    auto testSocket = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(testSocket, 0) << "Failed to create test socket";
    auto socketGuard = std::unique_ptr<int, std::function<void(int*)>>(
    new int(testSocket), [](int* fd) { if (*fd >= 0) ::close(*fd); delete fd; });
    ASSERT_NO_FATAL_FAILURE({DSoftbusAdapterImpl::GetInstance()->ConfigTcpAlive(testSocket);});
    RemovePermission();
}

/**
 * @tc.name: TestConfigTcpAliveinterval
 * @tc.desc: Test ConfigTcpAlive_interval
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, ConfigTcpAliveinterval, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    std::unique_ptr<int, std::function<void(int*)>> testSocket(std::make_unique<int>((AF_INET, SOCK_STREAM, 0))
    [](int* fd) { if (*fd >= 0) ::close(*fd); delete fd; });
    ASSERT_GE(*testSocket, 0) << "Failed to create test socket";
    ASSERT_NO_FATAL_FAILURE({DSoftbusAdapterImpl::GetInstance()->ConfigTcpAlive(*testSocket);});
    RemovePermission();
}

/**
 * @tc.name: TestConfigTcpAliveenable
 * @tc.desc: Test ConfigTcpAlive_enable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, ConfigTcpAliveenable, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto testSocket = std::unique_ptr<int, std::function<void(int*)>>(
    new int(::socket(AF_INET, SOCK_STREAM, 0)),
    [](int* fd) { if (*fd >= 0) ::close(*fd); delete fd; });
    ASSERT_GE(*testSocket, 0) << "Failed to create test socket";
    ASSERT_NO_FATAL_FAILURE({DSoftbusAdapterImpl::GetInstance()->ConfigTcpAlive(*testSocket);});
    RemovePermission();
}

/**
 * @tc.name: TestConfigTcpAliveTimeoutMs
 * @tc.desc: Test ConfigTcpAlive_TimeoutMs
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, ConfigTcpAliveTimeoutMs, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    auto testSocket = std::unique_ptr<int, std::function<void(int*)>>(
    new int(::socket(AF_INET, SOCK_STREAM, 0)),
    [](int* fd) { if (*fd >= 0) ::close(*fd); delete fd; });
    ASSERT_GE(*testSocket, 0) << "Failed to create socket";
    ASSERT_NO_FATAL_FAILURE({DSoftbusAdapterImpl::GetInstance()->ConfigTcpAlive(*testSocket);});
}

/**
 * @tc.name: TestConfigTcpAlivekeepAliveTimeout
 * @tc.desc: Test ConfigTcpAlive_keepAliveTimeout
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, ConfigTcpAlivekeepAliveTimeout, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    auto testSocket = std::unique_ptr<int, std::function<void(int*)>>(
    new int(::socket(AF_INET, SOCK_STREAM, 0)),
    [](int* fd) { if (*fd >= 0) ::close(*fd); delete fd; });
    ASSERT_GE(*testSocket, 0) << "Failed to create socket";
    RemovePermission();
}
/**
 * @tc.name: TestCheckDeviceOnline
 * @tc.desc: Test CheckDeviceOnline
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, CheckDeviceOnline, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    std::string networkId = "test_device";
    auto adapter = DSoftbusAdapterImpl::GetInstance();
    bool isOnline = adapter->CheckDeviceOnline(networkId);
    EXPECT_FALSE(isOnline) << "Test device should not be online";
    RemovePermission();
}

/**
 * @tc.name: TestStopHeartBeat
 * @tc.desc: Test StopHeartBeat
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, StopHeartBeat, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    std::string networkId = "test_device";
    ASSERT_NO_FATAL_FAILURE({ DSoftbusAdapterImpl::GetInstance()->StopHeartBeat(networkId);});
    EXPECT_FALSE(adapter->GetHeartBeatState(networkId));
    RemovePermission();
}

/**
 * @tc.name: TestStartHeartBeat
 * @tc.desc: Test StartHeartBeat
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, StartHeartBeat, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    std::string networkId = "test_device_start";
    ASSERT_NO_FATAL_FAILURE({ DSoftbusAdapterImpl::GetInstance()->StartHeartBeat (networkId);});
    RemovePermission();
}

/**
 * @tc.name: TestStartHeartBeat_GetHeartBeatState
 * @tc.desc: Test StartHeartBeat_GetHeartBeatState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, StartHeartBeatGetHeartBeatState, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    auto adapter = DSoftbusAdapterImpl::GetInstance();
    std::string networkId = "test_device_start";
    bool state = false;
    ASSERT_NO_FATAL_FAILURE(state = adapter->GetHeartBeatState(networkId));
    RemovePermission();
}

/**
 * @tc.name: TestStartHeartBeat_UpdateHeartBeat
 * @tc.desc: Test StartHeartBeat_UpdateHeartBeat
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusAdapterTest, StartHeartBeatUpdateHeartBeat, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    auto adapter = DSoftbusAdapterImpl::GetInstance();
    std::string networkId = "test_device_update_state";
    ASSERT_NO_FATAL_FAILURE(adapter->UpdateHeartBeatState(networkId, false));
    bool beforeState = false;
    ASSERT_NO_FATAL_FAILURE(beforeState = adapter->GetHeartBeatState(networkId));
    EXPECT_FALSE(beforeState);
    ASSERT_NO_FATAL_FAILURE(adapter->StartHeartBeat(networkId));
    bool afterState = false;
    ASSERT_NO_FATAL_FAILURE(afterState = adapter->GetHeartBeatState(networkId));
    RemovePermission();
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS