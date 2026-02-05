/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "stream_session.h"

#include <cinttypes>
#include <sstream>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "devicestatus_define.h"
#include "devicestatus_proto.h"
#include "stream_socket.h"

#undef LOG_TAG
#define LOG_TAG "StreamSession"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
const std::string FOUNDATION { "foundation" };
constexpr uint64_t DOMAIN_ID { 0xD002220 };
} // namespace

StreamSession::StreamSession(const std::string &programName, int32_t moduleType, int32_t fd, int32_t uid, int32_t pid)
    : fd_(fd), pid_(pid)
{}

bool StreamSession::SendMsg(const char *buf, size_t size) const
{
    CHKPF(buf);
    if ((size == 0) || (size > MAX_PACKET_BUF_SIZE)) {
        FI_HILOGE("buf size:%{public}zu", size);
        return false;
    }
    if (fd_ < 0) {
        FI_HILOGE("The fd_ is less than 0");
        return false;
    }

    int32_t idx = 0;
    int32_t retryCount = 0;
    const int32_t bufSize = static_cast<int32_t>(size);
    int32_t remSize = bufSize;
    while (remSize > 0 && retryCount < SEND_RETRY_LIMIT) {
        retryCount += 1;
        ssize_t count = send(fd_, &buf[idx], remSize, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (count < 0) {
            if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK) {
                usleep(SEND_RETRY_SLEEP_TIME);
                FI_HILOGW("Continue for errno EAGAIN|EINTR|EWOULDBLOCK, errno:%{public}d", errno);
                continue;
            }
            FI_HILOGE("Send return failed, error:%{public}d, fd:%{public}d", errno, fd_);
            return false;
        }
        idx += count;
        remSize -= count;
        if (remSize > 0) {
            usleep(SEND_RETRY_SLEEP_TIME);
        }
    }
    if (retryCount >= SEND_RETRY_LIMIT || remSize != 0) {
        FI_HILOGE("Send too many times:%{public}d/%{public}d, size:%{public}d/%{public}d, fd:%{public}d",
            retryCount, SEND_RETRY_LIMIT, idx, bufSize, fd_);
        return false;
    }
    return true;
}

void StreamSession::Close()
{
    CALL_DEBUG_ENTER;
    FI_HILOGD("Enter fd_:%{public}d", fd_);
    if (fd_ >= 0) {
        if (fdsan_close_with_tag(fd_, DOMAIN_ID) < 0) {
            FI_HILOGE("Close fd failed, error:%{public}s, fd_:%{public}d", strerror(errno), fd_);
        }
        fd_ = -1;
    }
}

bool StreamSession::SendMsg(NetPacket &pkt) const
{
    if (pkt.ChkRWError()) {
        FI_HILOGE("Read and write status is error");
        return false;
    }
    StreamBuffer buf;
    if (!pkt.MakeData(buf)) {
        FI_HILOGE("Failed to buffer packet");
        return false;
    }
    return SendMsg(buf.Data(), buf.Size());
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS