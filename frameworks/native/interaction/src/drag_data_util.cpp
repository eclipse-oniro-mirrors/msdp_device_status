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

#include "drag_data_util.h"

#include "parcel.h"

#include "drag_data_packer.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

int32_t DragDataUtil::Marshalling(const DragData &dragData, Parcel &data, bool isCross)
{
    return DragDataPacker::Marshalling(dragData, data, isCross);
}

int32_t DragDataUtil::UnMarshalling(Parcel &data, DragData &dragData, bool isCross)
{
    return DragDataPacker::UnMarshalling(data, dragData, isCross);
}

int32_t DragDataUtil::MarshallingSummarys2(const DragData &dragData, Parcel &data)
{
    return DragDataPacker::MarshallingSummarys2(dragData, data);
}

int32_t DragDataUtil::UnMarshallingSummarys2(Parcel &data, DragData &dragData)
{
    return DragDataPacker::UnMarshallingSummarys2(data, dragData);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
