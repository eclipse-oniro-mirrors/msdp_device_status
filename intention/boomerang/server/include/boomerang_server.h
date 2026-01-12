/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef BOOMERANG_SERVER_H
#define BOOMERANG_SERVER_H

#include "nocopyable.h"

#include "accesstoken_kit.h"

#include "devicestatus_manager.h"
#include "i_plugin.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class BoomerangServer {
public:
    BoomerangServer();
    ~BoomerangServer() = default;
    DISALLOW_COPY_AND_MOVE(BoomerangServer);
    bool IsSystemServiceCalling(const CallingContext &context);
    bool IsSystemHAPCalling(const CallingContext &context);
    void DumpDeviceStatusSubscriber(int32_t fd) const;
    void DumpDeviceStatusChanges(int32_t fd) const;
    void DumpCurrentDeviceStatus(int32_t fd);
    int32_t SubscribeCallback(const CallingContext &context, int32_t type, const std::string& bundleName,
        const sptr<IRemoteBoomerangCallback>& subCallback);
    int32_t UnsubscribeCallback(const CallingContext &context, int32_t type, const std::string& bundleName,
        const sptr<IRemoteBoomerangCallback>& unsubCallback);
    int32_t NotifyMetadataBindingEvent(const CallingContext &context, const std::string& bundleName,
        const sptr<IRemoteBoomerangCallback>& notifyCallback);
    int32_t SubmitMetadata(const CallingContext &context, const std::string& metaData);
    int32_t BoomerangEncodeImage(const CallingContext &context, const std::shared_ptr<Media::PixelMap>& pixelMap,
        const std::string& metaData, const sptr<IRemoteBoomerangCallback>& encodeCallback);
    int32_t BoomerangDecodeImage(const CallingContext &context, const std::shared_ptr<Media::PixelMap>& pixelMap,
        const sptr<IRemoteBoomerangCallback>& decodeCallback);

private:
    Data GetCache(const CallingContext &context, const Type &type);
    void ReportSensorSysEvent(const CallingContext &context, int32_t type, bool enable);
    bool IsDeviceSupport();

    DeviceStatusManager manager_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // BOOMERANG_SERVER_H