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

#include "boomerang_manager.h"

#include "include/util.h"

#include "devicestatus_client.h"
#include "devicestatus_common.h"
#include "devicestatus_define.h"
#include "intention_manager.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

BoomerangManager& BoomerangManager::GetInstance()
{
    static BoomerangManager instance;
    return instance;
}

int32_t BoomerangManager::SubscribeCallback(BoomerangType type, const std::string &bundleName,
    sptr<IRemoteBoomerangCallback> callback)
{
    return INTER_MGR_IMPL.SubscribeCallback(type, bundleName, callback);
}

int32_t BoomerangManager::UnsubscribeCallback(BoomerangType type, const std::string &bundleName,
    sptr<IRemoteBoomerangCallback> callback)
{
    return INTER_MGR_IMPL.UnsubscribeCallback(type, bundleName, callback);
}

int32_t BoomerangManager::NotifyMetadataBindingEvent(const std::string &bundleName,
    sptr<IRemoteBoomerangCallback> callback)
{
    return INTER_MGR_IMPL.NotifyMetadataBindingEvent(bundleName, callback);
}

int32_t BoomerangManager::SubmitMetadata(const std::string &metadata)
{
    return INTER_MGR_IMPL.SubmitMetadata(metadata);
}

int32_t BoomerangManager::BoomerangEncodeImage(std::shared_ptr<Media::PixelMap> pixelMap,
    const std::string &matedata, sptr<IRemoteBoomerangCallback> callback)
{
    return INTER_MGR_IMPL.BoomerangEncodeImage(pixelMap, matedata, callback);
}

int32_t BoomerangManager::BoomerangDecodeImage(std::shared_ptr<Media::PixelMap> pixelMap,
    sptr<IRemoteBoomerangCallback> callback)
{
    return INTER_MGR_IMPL.BoomerangDecodeImage(pixelMap, callback);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS