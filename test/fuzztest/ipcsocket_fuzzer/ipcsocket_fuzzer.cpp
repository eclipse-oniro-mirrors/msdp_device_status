/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "ipcsocket_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include "singleton.h"
#include "ipc_skeleton.h"

#include "devicestatus_define.h"
#include "socket_client.h"
#include "socket_session_manager.h"
#include "socket_session.h"
#include "socket_connection.h"
#include "stream_client.h"
#include "dsoftbus_adapter_impl.h"
#include "message_parcel.h"

#undef LOG_TAG
#define LOG_TAG "IpcSocketFuzzTest"
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
#define SERVER_SESSION_NAME "ohos.msdp.device_status.intention.serversession"
#define FI_PKG_NAME "ohos.msdp.fusioninteraction"
const std::u16string FORMMGR_INTERFACE_TOKEN { u"ohos.msdp.Idevicestatus" };
inline constexpr int32_t MAX_EVENT_SIZE { 100 };

#define TEST_TEMP_FILE "/data/test/testfile1"
namespace OHOS {


bool SocketConnectionFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return false;
    }
    FuzzedDataProvider provider(data, size);
    auto recv = [](const NetPacket &pkt) {
        return;
    };
    auto onDisconnected = []() {
        return;
    };

    int32_t fd = open(TEST_TEMP_FILE, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
    if(write(fd, data, size) != (ssize_t)size) {
        close(fd);
        return false;
    }
    SocketConnection socketConnection(fd, recv, onDisconnected);
    auto socket = []() {
        return 0;
    };
    struct epoll_event ev{};
    auto client = std::make_unique<SocketClient>();
    MessageId msgId = static_cast<MessageId>(provider.ConsumeIntegralInRange<int32_t>(0, 31));
    NetPacket pkt(msgId);
    client->OnPacket(pkt);
    const std::string programName(GetProgramName());
    int32_t pid = IPCSkeleton::GetCallingPid();
    int32_t uid = IPCSkeleton::GetCallingUid();
    SocketSession socketSession(programName, 1, 1, fd, uid, pid);
    socketSession.SendMsg(pkt);
    socketSession.Dispatch(ev);
    socketConnection.OnReadable(fd);
    socketConnection.OnShutdown(fd);
    socketConnection.OnException(fd);
    Msdp::DeviceStatus::SocketConnection::Connect(socket, recv, onDisconnected);
    client = nullptr;
    close(fd);
    return true;
}

} // namespace OHOS
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    OHOS::SocketConnectionFuzzTest(data, size);
    return 0;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS