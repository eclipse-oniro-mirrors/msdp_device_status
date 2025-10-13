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

#include "on_screen_client.h"

#include "devicestatus_define.h"
#include "intention_client.h"

#undef LOG_TAG
#define LOG_TAG "OnScreenClient"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
int32_t OnScreenClient::GetPageContent(const ContentOption& option, PageContent& pageContent)
{
    int32_t ret = INTENTION_CLIENT->GetPageContent(option, pageContent);
    if (ret != RET_OK) {
        FI_HILOGE("GetPageContent failed, ret = %{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t OnScreenClient::SendControlEvent(const ControlEvent& event)
{
    int32_t ret = INTENTION_CLIENT->SendControlEvent(event);
    if (ret != RET_OK) {
        FI_HILOGE("SendControlEvent failed, ret = %{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t OnScreenClient::RegisterScreenEventCallback(int32_t windowId, const std::string& event,
    const sptr<IRemoteOnScreenCallback>& callback)
{
    auto ret = INTENTION_CLIENT->RegisterScreenEventCallback(windowId, event, callback);
    if (ret != RET_OK) {
        FI_HILOGE("RegisterScreenEventCallback failed, ret = %{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t OnScreenClient::UnregisterScreenEventCallback(int32_t windowId, const std::string& event,
    const sptr<IRemoteOnScreenCallback>& callback)
{
    auto ret = INTENTION_CLIENT->UnregisterScreenEventCallback(windowId, event, callback);
    if (ret != RET_OK) {
        FI_HILOGE("UnregisterScreenEventCallback failed, ret = %{public}d", ret);
        return ret;
    }
    return RET_OK;
}

int32_t OnScreenClient::IsParallelFeatureEnabled(int32_t windowId, int32_t& outStatus)
{
    auto ret = INTENTION_CLIENT->IsParallelFeatureEnabled(windowId, outStatus);
    return ret;
}

} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS