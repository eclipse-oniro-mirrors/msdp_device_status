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

#include "on_screen_manager.h"

#include "include/util.h"

#include "devicestatus_client.h"
#include "devicestatus_common.h"
#include "devicestatus_define.h"
#include "intention_manager.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
namespace {
#ifdef DEVICE_STATUS_PHONE_STANDARD_LITE
constexpr int32_t RET_NO_SUPPORT = 801;
#endif
};
OnScreenManager& OnScreenManager::GetInstance()
{
    static OnScreenManager instance;
    return instance;
}

int32_t OnScreenManager::GetPageContent(const ContentOption& option, PageContent& pageContent)
{
    return INTER_MGR_IMPL.GetPageContent(option, pageContent);
}

int32_t OnScreenManager::SendControlEvent(const ControlEvent& event)
{
    return INTER_MGR_IMPL.SendControlEvent(event);
}

int32_t OnScreenManager::RegisterScreenEventCallback(int32_t windowId, std::string event,
    sptr<IRemoteOnScreenCallback> callback)
{
    return INTER_MGR_IMPL.RegisterScreenEventCallback(windowId, event, callback);
}

int32_t OnScreenManager::UnregisterScreenEventCallback(int32_t windowId, std::string event,
    sptr<IRemoteOnScreenCallback> callback)
{
    return INTER_MGR_IMPL.UnregisterScreenEventCallback(windowId, event, callback);
}

int32_t OnScreenManager::IsParallelFeatureEnabled(int32_t windowId, int32_t& outStatus)
{
    return INTER_MGR_IMPL.IsParallelFeatureEnabled(windowId, outStatus);
}

int32_t OnScreenManager::GetLiveStatus()
{
    return INTER_MGR_IMPL.GetLiveStatus();
}

int32_t OnScreenManager::RegisterAwarenessCallback(const AwarenessCap& cap, sptr<IRemoteOnScreenCallback> callback,
    const AwarenessOptions& option)
{
#ifdef DEVICE_STATUS_PHONE_STANDARD_LITE
    return RET_NO_SUPPORT;
#else
    return INTER_MGR_IMPL.RegisterAwarenessCallback(cap, callback, option);
#endif
}
int32_t OnScreenManager::UnregisterAwarenessCallback(const AwarenessCap& cap, sptr<IRemoteOnScreenCallback> callback)
{
#ifdef DEVICE_STATUS_PHONE_STANDARD_LITE
    return RET_NO_SUPPORT;
#else
    return INTER_MGR_IMPL.UnregisterAwarenessCallback(cap, callback);
#endif
}

int32_t OnScreenManager::Trigger(const AwarenessCap& cap, const AwarenessOptions& option,
    OnscreenAwarenessInfo& info)
{
#ifdef DEVICE_STATUS_PHONE_STANDARD_LITE
    return RET_NO_SUPPORT;
#else
    return INTER_MGR_IMPL.Trigger(cap, option, info);
#endif
}
} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS