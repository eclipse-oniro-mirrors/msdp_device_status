/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HOVER_HAND_DATA_H
#define HOVER_HAND_DATA_H

#include <cstdint>
#include <sstream>
#include "parcel.h"
namespace OHOS {
namespace Msdp {
namespace UserStatusAwareness {
enum class HoverHandAction : int32_t { INVALID = -1, BEGIN = 0, DOWN = BEGIN, UP = 1, END = UP };

struct HoverHandDetectionArea : public Parcelable {
    int32_t left = 0;
    int32_t top = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    bool operator==(const HoverHandDetectionArea &area) const
    {
        return left == area.left && top == area.top && width == area.width && height == area.height;
    };
    inline std::string ToString() const
    {
        std::stringstream ss;
        ss << "[top=" << top << ", left=" << left << ", width=" << width << ", height=" << height << "]";
        return ss.str();
    }

    bool ReadFromParcel(Parcel &in)
    {
        if (!in.ReadInt32(left)) {
            return false;
        }
        if (!in.ReadInt32(top)) {
            return false;
        }
        if (!in.ReadUint32(width)) {
            return false;
        }
        if (!in.ReadUint32(height)) {
            return false;
        }
        return true;
    }

    bool Marshalling(Parcel &out) const
    {
        if (!out.WriteInt32(left)) {
            return false;
        }
        if (!out.WriteInt32(top)) {
            return false;
        }
        if (!out.WriteUint32(width)) {
            return false;
        }
        if (!out.WriteUint32(height)) {
            return false;
        }
        return true;
    }

    static HoverHandDetectionArea *Unmarshalling(Parcel &in)
    {
        HoverHandDetectionArea *data = new (std::nothrow) HoverHandDetectionArea();
        if (data != nullptr && !data->ReadFromParcel(in)) {
            delete data;
            data = nullptr;
        }
        return data;
    }
};
struct HoverHandOptions {
    HoverHandDetectionArea area;
    uint32_t duration{ 5 };
};
} // namespace UserStatusAwareness
} // namespace Msdp
} // namespace OHOS

#endif // HOVER_HAND_DATA_H
