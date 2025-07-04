/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef DEVICESTATUS_COMMON_H
#define DEVICESTATUS_COMMON_H

#include <cstdint>
#include <type_traits>

#include "devicestatus_errors.h"
#include "fi_log.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
#define DEV_RET_IF_NULL_WITH_RET(cond, retval) if (cond) {return (retval);}
#define DEV_RET_IF_NULL(cond) if (cond) {return;}
#define DEV_RET_IF_NULL_WITH_LOG(cond, loginfo) \
    do { \
        if (cond) { \
            FI_HILOGE("%{public}s "#loginfo" ", __func__); \
            return; \
        } \
    } while (0) \

#define WRITEBOOL(parcel, data, ...) \
    do { \
        if (!(parcel).WriteBool(data)) { \
            FI_HILOGE("WriteBool "#data" failed"); \
            return __VA_ARGS__; \
        } \
    } while (0)

#define WRITEINT32(parcel, data, ...) \
    do { \
        if (!(parcel).WriteInt32(data)) { \
            FI_HILOGE("WriteInt32 "#data" failed"); \
            return __VA_ARGS__; \
        } \
    } while (0)

#define WRITEINT64(parcel, data, ...) \
    do { \
        if (!(parcel).WriteInt64(data)) { \
            FI_HILOGE("WriteInt64 "#data" failed"); \
            return __VA_ARGS__; \
        } \
    } while (0)

#define WRITEUINT32(parcel, data, ...) \
    do { \
        if (!(parcel).WriteUint32(data)) { \
            FI_HILOGE("WriteUint32 "#data" failed"); \
            return __VA_ARGS__; \
        } \
    } while (0)

#define WRITEDOUBLE(parcel, data, ...) \
    do { \
        if (!(parcel).WriteDouble(data)) { \
            FI_HILOGE("WriteDouble "#data" failed"); \
            return __VA_ARGS__; \
        } \
    } while (0)

#define WRITEFLOAT(parcel, data, ...) \
    do { \
        if (!(parcel).WriteFloat(data)) { \
            FI_HILOGE("WriteFloat "#data" failed"); \
            return __VA_ARGS__; \
        } \
    } while (0)

#define WRITEUINT64(parcel, data, ...) \
    do { \
        if (!(parcel).WriteUint64(data)) { \
            FI_HILOGE("WriteUint64 "#data" failed"); \
            return __VA_ARGS__; \
        } \
    } while (0)

#define WRITESTRING(parcel, data, ...) \
    do { \
        if (!(parcel).WriteString(data)) { \
            FI_HILOGE("WriteString "#data" failed"); \
            return __VA_ARGS__; \
        } \
    } while (0)

#define WRITESTRING16(parcel, data, ...) \
    do { \
        if (!(parcel).WriteString16(data)) { \
            FI_HILOGE("WriteString16 "#data" failed"); \
            return __VA_ARGS__; \
        } \
    } while (0)

#define WRITEREMOTEOBJECT(parcel, data, ...) \
    do { \
        if (!(parcel).WriteRemoteObject(data)) { \
            FI_HILOGE("WriteRemoteObject "#data" failed"); \
            return __VA_ARGS__; \
        } \
    } while (0)

#define WRITEUINT8VECTOR(parcel, data, ...) \
    do { \
        if (!(parcel).WriteUInt8Vector(data)) { \
            FI_HILOGE("WriteUInt8Vector "#data" failed"); \
            return __VA_ARGS__; \
        } \
    } while (0)

#define WRITEINT32VECTOR(parcel, data, ...) \
    do { \
        if (!(parcel).WriteInt32Vector(data)) { \
            FI_HILOGE("WriteInt32Vector "#data" failed"); \
            return __VA_ARGS__; \
        } \
    } while (0)

#define WRITEFLOATVECTOR(parcel, data, ...) \
    do { \
        if (!(parcel).WriteFloatVector(data)) { \
            FI_HILOGE("WriteFloatVector "#data" failed"); \
            return __VA_ARGS__; \
        } \
    } while (0)

#define READBOOL(parcel, data, ...) \
    do { \
        if (!(parcel).ReadBool(data)) { \
            FI_HILOGE("ReadBool "#data" failed"); \
            return __VA_ARGS__; \
        } \
    } while (0)

#define READINT32(parcel, data, ...) \
    do { \
        if (!(parcel).ReadInt32(data)) { \
            FI_HILOGE("ReadInt32 "#data" failed"); \
            return __VA_ARGS__; \
        } \
    } while (0)

#define READINT64(parcel, data, ...) \
    do { \
        if (!(parcel).ReadInt64(data)) { \
            FI_HILOGE("ReadInt64 "#data" failed"); \
            return __VA_ARGS__; \
        } \
    } while (0)

#define READUINT32(parcel, data, ...) \
    do { \
        if (!(parcel).ReadUint32(data)) { \
            FI_HILOGE("ReadUint32 "#data" failed"); \
            return __VA_ARGS__; \
        } \
    } while (0)

#define READDOUBLE(parcel, data, ...) \
    do { \
        if (!(parcel).ReadDouble(data)) { \
            FI_HILOGE("ReadDouble "#data" failed"); \
            return __VA_ARGS__; \
        } \
    } while (0)

#define READFLOAT(parcel, data, ...) \
    do { \
        if (!(parcel).ReadFloat(data)) { \
            FI_HILOGE("ReadFloat "#data" failed"); \
            return __VA_ARGS__; \
        } \
    } while (0)

#define READUINT64(parcel, data, ...) \
    do { \
        if (!(parcel).ReadUint64(data)) { \
            FI_HILOGE("ReadUint64 "#data" failed"); \
            return __VA_ARGS__; \
        } \
    } while (0)

#define READSTRING(parcel, data, ...) \
    do { \
        if (!(parcel).ReadString(data)) { \
            FI_HILOGE("ReadString "#data" failed"); \
            return __VA_ARGS__; \
        } \
    } while (0)

#define READUINT8VECTOR(parcel, data, ...) \
    do { \
        if (!(parcel).ReadUInt8Vector(&data)) { \
                FI_HILOGE("ReadUInt8Vector "#data" failed"); \
                return __VA_ARGS__; \
            } \
    } while (0)

#define READSTRING16(parcel, data, ...) \
    do { \
        if (!(parcel).ReadString16(data)) { \
            FI_HILOGE("ReadString16 "#data" failed"); \
            return __VA_ARGS__; \
        } \
    } while (0)

#define READINT32VECTOR(parcel, data, ...) \
    do { \
        if (!(parcel).ReadInt32Vector(&data)) { \
            FI_HILOGE("ReadInt32Vector "#data" failed"); \
            return __VA_ARGS__; \
        } \
    } while (0)

#define READFLOATVECTOR(parcel, data, ...) \
    do { \
        if (!(parcel).ReadFloatVector(&data)) { \
            FI_HILOGE("ReadFloatVector "#data" failed"); \
            return __VA_ARGS__; \
        } \
    } while (0)

template<typename E>
constexpr auto DeviceStatusToUnderlying(E e) noexcept
{
    return static_cast<std::underlying_type_t<E>>(e);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS

#endif // DEVICESTATUS_COMMON_H
