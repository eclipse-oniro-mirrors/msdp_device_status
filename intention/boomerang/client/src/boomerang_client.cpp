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

#undef LOG_TAG
#define LOG_TAG "BoomerangClient"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

int32_t BoomerangClient::SubscribeCallback(ITunnelClient &tunnel, BoomerangType type, std::string bundleName,
    sptr<IRemoteBoomerangCallback> callback)
{
    SubscribeBoomerangParam param { type, bundleName, callback };
    DefaultReply reply {};
    int32_t ret = tunnel.AddWatch(Intention::BOOMERANG, BoomerangRequestID::ADD_BOOMERAMG_LISTENER, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("SubscribeBoomerang fail, error:%{public}d", ret);
    }
    return ret;
}

int32_t BoomerangClient::UnsubscribeCallback(ITunnelClient &tunnel, BoomerangType type, std::string bundleName,
    sptr<IRemoteBoomerangCallback> callback)
{
    SubscribeBoomerangParam param { type, bundleName, callback };
    DefaultReply reply {};
    int32_t ret = tunnel.RemoveWatch(Intention::BOOMERANG, BoomerangRequestID::REMOVE_BOOMERAMG_LISTENER, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("UnsubscribeBoomerang fail, error:%{public}d", ret);
    }
    return ret;
}

int32_t BoomerangClient::NotifyMetadataBindingEvent(ITunnelClient &tunnel, std::string bundleName,
    sptr<IRemoteBoomerangCallback> callback)
{
    NotifyMetadataParam param { bundleName, callback };
    DefaultReply reply {};
    int32_t ret = tunnel.AddWatch(Intention::BOOMERANG, BoomerangRequestID::NOTIFY_METADATA, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("UnsubscribeBoomerang fail, error:%{public}d", ret);
    }
    return ret;
}

int32_t BoomerangClient::SubmitMetadata(ITunnelClient &tunnel, std::string metadata)
{
    MetadataParam param { metadata };
    DefaultReply reply {};
    int32_t ret = tunnel.SetParam(Intention::BOOMERANG, BoomerangRequestID::SUBMIT_METADATA, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("UnsubscribeBoomerang fail, error:%{public}d", ret);
    }
    return ret;
}

int32_t BoomerangClient::BoomerangEncodeImage(ITunnelClient &tunnel, std::shared_ptr<Media::PixelMap> pixelMap,
    std::string matedata, sptr<IRemoteBoomerangCallback> callback)
{
    EncodeImageParam param { pixelMap, matedata, callback };
    DefaultReply reply {};
    int32_t ret = tunnel.AddWatch(Intention::BOOMERANG, BoomerangRequestID::ENCODE_IMAGE, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("BoomerangEncodeImage fail, error:%{public}d", ret);
    }
    return ret;
}

int32_t BoomerangClient::BoomerangDecodeImage(ITunnelClient &tunnel, std::shared_ptr<Media::PixelMap> pixelMap,
    sptr<IRemoteBoomerangCallback> callback)
{
    DecodeImageParam param { pixelMap, callback };
    DefaultReply reply {};
    int32_t ret = tunnel.AddWatch(Intention::BOOMERANG, BoomerangRequestID::DECODE_IMAGE, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("BoomerangEncodeImage fail, error:%{public}d", ret);
    }
    return ret;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS