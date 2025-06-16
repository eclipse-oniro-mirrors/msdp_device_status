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

#ifndef SURFACE_CAPTURE_CALLBACK_H
#define SURFACE_CAPTURE_CALLBACK_H

#include <memory>

#include "pixel_map.h"
#include "transaction/rs_render_service_client.h"

#include "devicestatus_manager.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class BoomerangSurfaceCaptureCallback : public OHOS::Rosen::SurfaceCaptureCallback {
public:
    void SetContent(DeviceStatusManager *deviceStatusManager)
    {
        deviceStatusManager_ = deviceStatusManager;
    }
    void OnSurfaceCapture(std::shared_ptr<Media::PixelMap> pixelmap) override;

private:
    DeviceStatusManager *deviceStatusManager_ { nullptr };
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // SURFACE_CAPTURE_CALLBACK_H