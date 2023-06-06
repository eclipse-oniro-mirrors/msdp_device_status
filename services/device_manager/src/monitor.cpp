/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "monitor.h"

#include <cstring>
#include <unistd.h>

#include <string_view>

#include <sys/epoll.h>

#include "devicestatus_define.h"
#include "fi_log.h"
#include "napi_constants.h"
#include "utility.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL { LOG_CORE, MSDP_DOMAIN_ID, "Monitor" };
} // namespace

void Monitor::Dispatch(const struct epoll_event &ev)
{
    if ((ev.events & EPOLLIN) == EPOLLIN) {
        ReceiveDevice();
    } else if ((ev.events & (EPOLLHUP | EPOLLERR)) != 0) {
        FI_HILOGE("Epoll hangup:%{public}s", strerror(errno));
    }
}

void Monitor::SetDeviceMgr(IDeviceMgr *devMgr)
{
    CALL_DEBUG_ENTER;
    CHKPV(devMgr);
    devMgr_ = devMgr;
}

int32_t Monitor::Enable()
{
    CALL_INFO_TRACE;
    int32_t ret = OpenConnection();
    if (ret == RET_OK) {
        ret = EnableReceiving();
        if (ret != RET_OK) {
            Disable();
        }
    }
    return ret;
}

void Monitor::Disable()
{
    CALL_INFO_TRACE;
    if (devWd_ >= 0) {
        int32_t ret = inotify_rm_watch(inotifyFd_, devWd_);
        if (ret != 0) {
            FI_HILOGE("inotify_rm_watch failed");
        }
        devWd_ = -1;
    }
    if (inotifyFd_ >= 0) {
        close(inotifyFd_);
        inotifyFd_ = -1;
    }
}

int32_t Monitor::OpenConnection()
{
    CALL_DEBUG_ENTER;
    inotifyFd_ = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (inotifyFd_ < 0) {
        FI_HILOGE("Initializing inotify failed:%{public}s", strerror(errno));
        return RET_ERR;
    }
    return RET_OK;
}

int32_t Monitor::EnableReceiving()
{
    CALL_DEBUG_ENTER;
    devWd_ = inotify_add_watch(inotifyFd_, DEV_INPUT_PATH.c_str(), IN_CREATE | IN_DELETE);
    if (devWd_ < 0) {
        FI_HILOGE("Watching (\'%{public}s\') failed:%{public}s", DEV_INPUT_PATH.c_str(), strerror(errno));
        return RET_ERR;
    }
    return RET_OK;
}

void Monitor::ReceiveDevice()
{
    CALL_INFO_TRACE;
    char buf[sizeof(struct inotify_event) + NAME_MAX + 1];
    size_t bufSize { sizeof(struct inotify_event) };
    ssize_t numRead { 0 };

    do {
        bufSize += sizeof(struct inotify_event);
        numRead = ::read(inotifyFd_, buf, bufSize);
    } while ((numRead < 0) && (errno == EINVAL) &&
             (bufSize + sizeof(struct inotify_event) <= sizeof(buf)));

    if (numRead < 0) {
        FI_HILOGE("Reading failed:%{public}s", strerror(errno));
        return;
    }
    if (numRead == 0) {
        FI_HILOGW("End of file encountered");
        return;
    }
    FI_HILOGD("Read %{public}zd bytes from inotify events", numRead);
    for (char *p = buf; p < buf + numRead;) {
        struct inotify_event *event = reinterpret_cast<struct inotify_event *>(p);
        HandleInotifyEvent(event);
        p += sizeof(struct inotify_event) + event->len;
    }
}

void Monitor::HandleInotifyEvent(struct inotify_event *event) const
{
    CALL_DEBUG_ENTER;
    CHKPV(event);
    if (Utility::IsEmpty(event->name)) {
        return;
    }
    std::string devNode { event->name };

    if ((event->mask & IN_CREATE) == IN_CREATE) {
        AddDevice(devNode);
    } else if ((event->mask & IN_DELETE) == IN_DELETE) {
        RemoveDevice(devNode);
    }
}

void Monitor::AddDevice(const std::string &devNode) const
{
    CALL_DEBUG_ENTER;
    CHKPV(devMgr_);
    devMgr_->AddDevice(devNode);
}

void Monitor::RemoveDevice(const std::string &devNode) const
{
    CALL_DEBUG_ENTER;
    CHKPV(devMgr_);
    devMgr_->RemoveDevice(devNode);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS