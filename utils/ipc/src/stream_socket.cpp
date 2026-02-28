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

#include "stream_socket.h"

#include <cinttypes>

#include "devicestatus_define.h"
#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "StreamSocket"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr uint64_t DOMAIN_ID { 0xD002220 };
} // namespace

StreamSocket::StreamSocket() {}

StreamSocket::~StreamSocket()
{
    Close();
    EpollClose();
}

int32_t StreamSocket::EpollCreate()
{
    CALL_INFO_TRACE;
    epollFd_ = ::epoll_create1(EPOLL_CLOEXEC);
    if (epollFd_ < 0) {
        FI_HILOGE("epoll_create1 failed:%{public}s", ::strerror(errno));
        return RET_ERR;
    }
    fdsan_exchange_owner_tag(epollFd_, 0, DOMAIN_ID);
    return RET_OK;
}

int32_t StreamSocket::EpollCtl(int32_t fd, int32_t op, struct epoll_event &event)
{
    if (fd < 0) {
        FI_HILOGE("Invalid fd:%{public}d", fd);
        return RET_ERR;
    }
    if (epollFd_ < 0) {
        FI_HILOGE("Invalid epollFd:%{public}d", epollFd_);
        return RET_ERR;
    }
    if (::epoll_ctl(epollFd_, op, fd, &event) != 0) {
        FI_HILOGE("epoll_ctl(%{public}d,%{public}d,%{public}d) failed:%{public}s", epollFd_, op, fd, ::strerror(errno));
        return RET_ERR;
    }
    return RET_OK;
}

int32_t StreamSocket::EpollWait(int32_t maxevents, int32_t timeout, struct epoll_event &events)
{
    if (epollFd_ < 0) {
        FI_HILOGE("Invalid epollFd:%{public}d", epollFd_);
        return RET_ERR;
    }
    return epoll_wait(epollFd_, &events, maxevents, timeout);
}

void StreamSocket::OnReadPackets(CircleStreamBuffer &circBuf, StreamSocket::PacketCallBackFun callbackFun)
{
    constexpr int32_t headSize = static_cast<int32_t>(sizeof(PackHead));
    for (int32_t i = 0; i < ONCE_PROCESS_NETPACKET_LIMIT; i++) {
        const int32_t residualSize = circBuf.ResidualSize();
        if (residualSize < headSize) {
            break;
        }
        int32_t dataSize = residualSize - headSize;
        char *buf = const_cast<char *>(circBuf.ReadBuf());
        CHKPB(buf);
        PackHead *head = reinterpret_cast<PackHead *>(buf);
        CHKPB(head);
        if ((static_cast<int32_t>(head->size) < 0) || (static_cast<size_t>(head->size) > MAX_PACKET_BUF_SIZE)) {
            FI_HILOGE("Packet header parsing error, and this error cannot be recovered, the buffer will be reset, "
                "head->size:%{public}d, residualSize:%{public}d", head->size, residualSize);
            circBuf.Reset();
            break;
        }
        if (head->size > dataSize) {
            break;
        }
        NetPacket pkt(head->idMsg);
        if ((head->size > 0) && (!pkt.Write(&buf[headSize], head->size))) {
            FI_HILOGW("Error writing data in the NetPacket, it will be retried next time, messageid:%{public}d, "
                "size:%{public}d", head->idMsg, head->size);
            break;
        }
        if (!circBuf.SeekReadPos(pkt.GetPacketLength())) {
            FI_HILOGW("Set read position error, and this error cannot be recovered, and the buffer will be reset, "
                "packetSize:%{public}d, residualSize:%{public}d", pkt.GetPacketLength(), residualSize);
            circBuf.Reset();
            break;
        }
        callbackFun(pkt);
        if (circBuf.empty()) {
            circBuf.Reset();
            break;
        }
    }
}

void StreamSocket::EpollClose()
{
    if (epollFd_ >= 0) {
        if (fdsan_close_with_tag(epollFd_, DOMAIN_ID) < 0) {
            FI_HILOGE("Close epoll fd failed, error:%{public}s, epollFd_:%{public}d", strerror(errno), epollFd_);
        }
        epollFd_ = -1;
    }
}

void StreamSocket::Close()
{
    if (fd_ >= 0) {
        int32_t rf = fdsan_close_with_tag(fd_, DOMAIN_ID);
        if (rf < 0) {
            FI_HILOGE("Socket close failed rf:%{public}d", rf);
        }
    }
    fd_ = -1;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS