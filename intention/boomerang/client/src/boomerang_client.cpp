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

#include "boomerang_client.h"

#include "default_params.h"
#include "devicestatus_define.h"
#include "boomerang_params.h"
#include "intention_client.h"

#undef LOG_TAG
#define LOG_TAG "BoomerangClient"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

int32_t BoomerangClient::SubscribeCallback(BoomerangType type, const std::string& bundleName,
    const sptr<IRemoteBoomerangCallback>& callback)
{
    int32_t ret = INTENTION_CLIENT->SubscribeCallback(type, bundleName, callback);
    if (ret != RET_OK) {
        FI_HILOGE("SubscribeBoomerang fail, error:%{public}d", ret);
    }
    return ret;
}

int32_t BoomerangClient::UnsubscribeCallback(BoomerangType type, const std::string& bundleName,
    const sptr<IRemoteBoomerangCallback>& callback)
{
    int32_t ret = INTENTION_CLIENT->UnsubscribeCallback(type, bundleName, callback);
    if (ret != RET_OK) {
        FI_HILOGE("UnsubscribeBoomerang fail, error:%{public}d", ret);
    }
    return ret;
}

int32_t BoomerangClient::NotifyMetadataBindingEvent(const std::string& bundleName,
    const sptr<IRemoteBoomerangCallback>& callback)
{
    int32_t ret = INTENTION_CLIENT->NotifyMetadataBindingEvent(bundleName, callback);
    if (ret != RET_OK) {
        FI_HILOGE("NotifyMetadataBindingEvent fail, error:%{public}d", ret);
    }
    return ret;
}

int32_t BoomerangClient::SubmitMetadata(const std::string& metaData)
{
    int32_t ret = INTENTION_CLIENT->SubmitMetadata(metaData);
    if (ret != RET_OK) {
        FI_HILOGE("SubmitMetadata fail, error:%{public}d", ret);
    }
    return ret;
}

int32_t BoomerangClient::BoomerangEncodeImage(const std::shared_ptr<Media::PixelMap>& pixelMap,
    const std::string& metaData, const sptr<IRemoteBoomerangCallback>& callback)
{
    int32_t ret = INTENTION_CLIENT->BoomerangEncodeImage(pixelMap, metaData, callback);
    if (ret != RET_OK) {
        FI_HILOGE("BoomerangEncodeImage fail, error:%{public}d", ret);
    }
    return ret;
}

int32_t BoomerangClient::BoomerangDecodeImage(const std::shared_ptr<Media::PixelMap>& pixelMap,
    const sptr<IRemoteBoomerangCallback>& callback)
{
    int32_t ret = INTENTION_CLIENT->BoomerangDecodeImage(pixelMap, callback);
    if (ret != RET_OK) {
        FI_HILOGE("BoomerangDecodeImage fail, error:%{public}d", ret);
    }
    return ret;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS