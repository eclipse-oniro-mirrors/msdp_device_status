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

#ifndef DEVICE_MANAGER_H
#define DEVICE_MANAGER_H

#include <future>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>

#include "nocopyable.h"

#include "enumerator.h"
#include "i_context.h"
#include "i_device_mgr.h"
#include "i_epoll_event_source.h"
#include "monitor.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class DeviceManager final : public IDeviceManager,
                            public IEpollEventSource {
public:
    DeviceManager();
    DISALLOW_COPY_AND_MOVE(DeviceManager);
    ~DeviceManager() = default;

    int32_t Init(IContext *context);
    int32_t Enable();
    int32_t Disable();
    int32_t GetFd() const override;
    void Dispatch(const struct epoll_event &ev) override;
    std::shared_ptr<IDevice> GetDevice(int32_t id) const override;
    int32_t AddDeviceObserver(std::weak_ptr<IDeviceObserver> observer) override;
    void RemoveDeviceObserver(std::weak_ptr<IDeviceObserver> observer) override;
    void RetriggerHotplug(std::weak_ptr<IDeviceObserver> observer) override;

private:
    class HotplugHandler final : public IDeviceMgr {
    public:
        explicit HotplugHandler(DeviceManager &devMgr);
        ~HotplugHandler() = default;

        void AddDevice(const std::string &devNode) override;
        void RemoveDevice(const std::string &devNode) override;

    private:
        DeviceManager &devMgr_;
    };

private:
    int32_t OnInit(IContext *context);
    int32_t OnEnable();
    int32_t OnDisable();
    int32_t OnEpollDispatch();
    int32_t ParseDeviceId(const std::string &devNode);
    void OnDeviceAdded(std::shared_ptr<IDevice> dev);
    void OnDeviceRemoved(std::shared_ptr<IDevice> dev);
    int32_t OnAddDeviceObserver(std::weak_ptr<IDeviceObserver> observer);
    int32_t OnRemoveDeviceObserver(std::weak_ptr<IDeviceObserver> observer);
    int32_t OnRetriggerHotplug(std::weak_ptr<IDeviceObserver> observer);
    int32_t EpollCreate();
    int32_t EpollAdd(IEpollEventSource *source);
    void EpollDel(IEpollEventSource *source);
    void EpollClose();
    int32_t RunGetDevice(std::packaged_task<std::shared_ptr<IDevice>(int32_t)> &task, int32_t id) const;
    std::shared_ptr<IDevice> OnGetDevice(int32_t id) const;
    std::shared_ptr<IDevice> AddDevice(const std::string &devNode);
    std::shared_ptr<IDevice> RemoveDevice(const std::string &devNode);
    std::shared_ptr<IDevice> FindDevice(const std::string &devPath);

private:
    IContext *context_ { nullptr };
    int32_t epollFd_ { -1 };
    Enumerator enumerator_;
    Monitor monitor_;
    HotplugHandler hotplug_;
    std::set<std::weak_ptr<IDeviceObserver>> observers_;
    std::unordered_map<int32_t, std::shared_ptr<IDevice>> devices_;
};

inline int32_t DeviceManager::GetFd() const
{
    return epollFd_;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DEVICE_MANAGER_H