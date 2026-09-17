/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef CAR_AWARENESS_TYPE_INNER_H
#define CAR_AWARENESS_TYPE_INNER_H

#include <map>
#include <string>
#include <variant>
#include "fi_log.h"

namespace OHOS {
namespace Msdp {

struct WriteResult {
    bool success = true;
};

template<typename Parcel>
inline WriteResult WriteBool(Parcel& parcel, bool data)
{
    WriteResult result;
    if (!parcel.WriteBool(data)) {
        FI_HILOGE("WriteBool failed");
        result.success = false;
    }
    return result;
}

template<typename Parcel>
inline WriteResult WriteInt32(Parcel& parcel, int32_t data)
{
    WriteResult result;
    if (!parcel.WriteInt32(data)) {
        FI_HILOGE("WriteInt32 failed");
        result.success = false;
    }
    return result;
}

template<typename Parcel>
inline WriteResult WriteString(Parcel& parcel, const std::string& data)
{
    WriteResult result;
    if (!parcel.WriteString(data)) {
        FI_HILOGE("WriteString failed");
        result.success = false;
    }
    return result;
}

template<typename Parcel>
inline WriteResult ReadBool(Parcel& parcel, bool& data)
{
    WriteResult result;
    if (!parcel.ReadBool(data)) {
        FI_HILOGE("ReadBool failed");
        result.success = false;
    }
    return result;
}

template<typename Parcel>
inline WriteResult ReadInt32(Parcel& parcel, int32_t& data)
{
    WriteResult result;
    if (!parcel.ReadInt32(data)) {
        FI_HILOGE("ReadInt32 failed");
        result.success = false;
    }
    return result;
}

template<typename Parcel>
inline WriteResult ReadString(Parcel& parcel, std::string& data)
{
    WriteResult result;
    if (!parcel.ReadString(data)) {
        FI_HILOGE("ReadString failed");
        result.success = false;
    }
    return result;
}

// 修改后的CarAwarenessOption - 使用扁平化map
// key=device名称（如"hvac"），value=function列表（逗号分隔，如"ac_on,ac_off"）
typedef struct CarAwarenessOption {
    std::map<std::string, std::string> entityInfo;
    CarAwarenessOption() = default;
} CarAwarenessOption;

typedef struct CarAwarenessEvent {
    int32_t type = -1;
    std::string eventData;
} CarAwarenessEvent;
}  // namespace Msdp
}  // namespace OHOS

#endif // CAR_AWARENESS_TYPE_INNER_H