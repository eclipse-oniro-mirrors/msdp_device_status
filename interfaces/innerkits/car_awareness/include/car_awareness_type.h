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

namespace OHOS {
namespace Msdp {

template<typename Parcel>
inline bool WriteBool(Parcel& parcel, bool data)
{
    return parcel.WriteBool(data);
}

template<typename Parcel>
inline bool WriteInt32(Parcel& parcel, int32_t data)
{
    return parcel.WriteInt32(data);
}

template<typename Parcel>
inline bool WriteString(Parcel& parcel, const std::string& data)
{
    return parcel.WriteString(data);
}

template<typename Parcel>
inline bool ReadBool(Parcel& parcel, bool& data)
{
    return parcel.ReadBool(data);
}

template<typename Parcel>
inline bool ReadInt32(Parcel& parcel, int32_t& data)
{
    return parcel.ReadInt32(data);
}

template<typename Parcel>
inline bool ReadString(Parcel& parcel, std::string& data)
{
    return parcel.ReadString(data);
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