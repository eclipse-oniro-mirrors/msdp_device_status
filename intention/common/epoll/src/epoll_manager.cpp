/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "epoll_manager.h"

#include <unistd.h>

#include "devicestatus_define.h"

#undef LOG_TAG
#define LOG_TAG "EpollManager"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr int32_t MAX_N_EVENTS { 64 };
constexpr uint64_t DOMAIN_ID { 0xD002220 };
} // namespace

EpollManager::~EpollManager()
{
    Close();
}

bool EpollManager::Open()
{
    if (epollFd_ != -1) {
        return true;
    }
    epollFd_ = ::epoll_create1(EPOLL_CLOEXEC);
    if (epollFd_ == -1) {
        FI_HILOGE("epoll_create1 failed:%{public}s", ::strerror(errno));
        return false;
    }
    fdsan_exchange_owner_tag(epollFd_, 0, DOMAIN_ID);
    return true;
}

void EpollManager::Close()
{
    if (epollFd_ != -1) {
        fdsan_close_with_tag(epollFd_, DOMAIN_ID);
        epollFd_ = -1;
    }
}

bool EpollManager::Add(std::shared_ptr<IEpollEventSource> source)
{
    CHKPF(source);
    auto [iter, isNew] = sources_.emplace(source->GetFd(), source);
    if (!isNew) {
        FI_HILOGW("Epoll source(%d) has been added", source->GetFd());
        return true;
    }
    struct epoll_event ev {};
    ev.events = source->GetEvents();
    ev.data.ptr = source.get();

    int32_t ret = ::epoll_ctl(epollFd_, EPOLL_CTL_ADD, source->GetFd(), &ev);
    if (ret != 0) {
        FI_HILOGE("epoll_ctl failed:%{public}s", ::strerror(errno));
        sources_.erase(iter);
        return false;
    }
    FI_HILOGI("Add epoll source(%d)", source->GetFd());
    return true;
}

void EpollManager::Remove(std::shared_ptr<IEpollEventSource> source)
{
    CHKPV(source);
    auto iter = sources_.find(source->GetFd());
    if (iter == sources_.cend()) {
        FI_HILOGE("No epoll source(%d)", source->GetFd());
        return;
    }
    FI_HILOGI("Remove epoll source(%d)", source->GetFd());
    int32_t ret = ::epoll_ctl(epollFd_, EPOLL_CTL_DEL, source->GetFd(), nullptr);
    if (ret != 0) {
        FI_HILOGE("epoll_ctl failed:%{public}s", ::strerror(errno));
    }
    FI_HILOGI("Close fd: %{public}d", source->GetFd());
    fdsan_close_with_tag(source->GetFd(), DOMAIN_ID);
    sources_.erase(iter);
}

bool EpollManager::Update(std::shared_ptr<IEpollEventSource> source)
{
    CHKPF(source);
    auto iter = sources_.find(source->GetFd());
    if (iter == sources_.cend()) {
        FI_HILOGE("No epoll source(%d)", source->GetFd());
        return false;
    }
    struct epoll_event ev {};
    ev.events = source->GetEvents();
    ev.data.ptr = source.get();

    int32_t ret = ::epoll_ctl(epollFd_, EPOLL_CTL_MOD, source->GetFd(), &ev);
    if (ret != 0) {
        FI_HILOGE("epoll_ctl failed:%{public}s", ::strerror(errno));
        return false;
    }
    sources_.insert_or_assign(source->GetFd(), source);
    return true;
}

int32_t EpollManager::Wait(struct epoll_event *events, int32_t maxevents)
{
    return WaitTimeout(events, maxevents, -1);
}

int32_t EpollManager::WaitTimeout(struct epoll_event *events, int32_t maxevents, int32_t timeout)
{
    int32_t ret = ::epoll_wait(epollFd_, events, maxevents, timeout);
    if (ret < 0) {
        FI_HILOGE("epoll_wait failed:%{public}s", ::strerror(errno));
    } else if (ret == 0) {
        FI_HILOGE("epoll_wait timeout");
    }
    return ret;
}

void EpollManager::Dispatch(const struct epoll_event &ev)
{
    CALL_DEBUG_ENTER;
    if ((ev.events & EPOLLIN) == EPOLLIN) {
        DispatchOne(ev);
    } else if ((ev.events & (EPOLLHUP | EPOLLERR)) != 0) {
        FI_HILOGE("Epoll hangup:%{public}s", ::strerror(errno));
    }
}

void EpollManager::DispatchOne(const struct epoll_event &ev)
{
    struct epoll_event evs[MAX_N_EVENTS];
    int32_t cnt = WaitTimeout(evs, MAX_N_EVENTS, 0);

    for (int32_t index = 0; index < cnt; ++index) {
        IEpollEventSource *source = reinterpret_cast<IEpollEventSource *>(evs[index].data.ptr);
        CHKPC(source);
        if ((evs[index].events & EPOLLIN) == EPOLLIN) {
            source->Dispatch(evs[index]);
        } else if ((evs[index].events & (EPOLLHUP | EPOLLERR)) != 0) {
            FI_HILOGE("Epoll hangup:%{public}s", ::strerror(errno));
        }
    }
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS