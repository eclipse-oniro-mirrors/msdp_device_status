/**
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

#ifndef ON_SCREEN_CALLBACK_PROXY_H
#define ON_SCREEN_CALLBACK_PROXY_H

#include <iremote_proxy.h>
#include <nocopyable.h>
#include <string>

#include "iremote_on_screen_callback.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
class OnScreenCallbackProxy : public IRemoteProxy<IRemoteOnScreenCallback> {
public:
    explicit OnScreenCallbackProxy(const sptr<IRemoteObject>& impl)
        : IRemoteProxy<IRemoteOnScreenCallback>(impl) {}
    DISALLOW_COPY_AND_MOVE(OnScreenCallbackProxy);
    ~OnScreenCallbackProxy() = default;
    virtual void OnScreenChange(const std::string& changeInfo) override;
    virtual void OnScreenAwareness(const OnscreenAwarenessInfo& info) override;

private:
    static inline BrokerDelegator<OnScreenCallbackProxy> delegator_;
};
} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS

#endif // ON_SCREEN_CALLBACK_PROXY_H