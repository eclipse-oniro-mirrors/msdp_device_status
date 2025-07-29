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

#ifndef DRAG_DATA_UTIL_H
#define DRAG_DATA_UTIL_H

#include "parcel.h"

#ifdef OHOS_BUILD_INTERNAL_DROP_ANIMATION
#include "dm_common.h"
#include "ui/rs_canvas_node.h"
#include "ui/rs_node.h"
#endif // OHOS_BUILD_INTERNAL_DROP_ANIMATION

#include "drag_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class DragDataUtil {
public:
    static int32_t Marshalling(const DragData &dragData, Parcel &data, bool isCross = true);
    static int32_t UnMarshalling(Parcel &data, DragData &dragData, bool isCross = true);
    static int32_t MarshallingDetailedSummarys(const DragData &dragData, Parcel &data);
    static int32_t UnMarshallingDetailedSummarys(Parcel &data, DragData &dragData);
    static int32_t MarshallingSummaryExpanding(const DragData &dragData, Parcel &data);
    static int32_t UnMarshallingSummaryExpanding(Parcel &data, DragData &dragData);
};

#ifdef OHOS_BUILD_INTERNAL_DROP_ANIMATION
struct DragInternalInfo {
    float positionX { -1.0f };
    float positionY { -1.0f };
    float scale { -1.0f };
    int32_t pixelMapX { -1 };
    int32_t pixelMapY { -1 };
    int32_t displayWidth { -1 };
    int32_t displayHeight { -1 };
    uint32_t argb { 0 };
    Rosen::Rotation rotation { Rosen::Rotation::ROTATION_0 };
    std::shared_ptr<Rosen::RSNode> rootNode { nullptr };
    std::shared_ptr<Rosen::RSNode> parentNode { nullptr };
    std::shared_ptr<Rosen::RSNode> curvesMaskNode { nullptr };
    std::shared_ptr<Rosen::RSNode> lightNode { nullptr };
    std::shared_ptr<Media::PixelMap> currentPixelMap { nullptr };
    std::vector<std::shared_ptr<Rosen::RSCanvasNode>> nodes;
    std::vector<std::shared_ptr<Rosen::RSCanvasNode>> multiSelectedNodes;
    std::vector<std::shared_ptr<Media::PixelMap>> multiSelectedPixelMaps;
};
#endif // OHOS_BUILD_INTERNAL_DROP_ANIMATION
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DRAG_DATA_UTIL_H
