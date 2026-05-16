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

#ifndef DEVICE_INFO_H
#define DEVICE_INFO_H

#include "nocopyable.h"
#include "parcel.h"
#include "string_ex.h"

namespace OHOS {
namespace Msdp {
enum MsdpDeviceType : uint32_t {
    TYPE_UNKNOWN = 0x00,
    TYPE_WIFI_CAMERA = 0x08,
    TYPE_AUDIO = 0x0A,
    TYPE_PC = 0x0C,
    TYPE_PHONE = 0x0E,
    TYPE_PAD = 0x11,
    TYPE_WATCH = 0x6D,
    TYPE_CAR = 0x83,
    TYPE_TV = 0x9C,
    TYPE_2IN1 = 0xA2F,
};

namespace UserStatusAwareness {
class DeviceInfo  : public Parcelable {
public:
    DeviceInfo() = default;
    DeviceInfo(const std::string& id, const std::string& name, const std::string networkId,
        uint32_t type) : deviceId_(id), type_(type), networkId_(networkId), deviceName_(name)
    {
    };
    ~DeviceInfo() = default;

    bool operator==(const DeviceInfo& device) const
    {
        return (deviceId_ == device.deviceId_);
    };

    bool operator<(const DeviceInfo& device) const
    {
        return (deviceId_ < device.deviceId_);
    };

    bool IsRichDevice() const
    {
        MsdpDeviceType deviceType = static_cast<MsdpDeviceType>(type_);
        return (deviceType == MsdpDeviceType::TYPE_PHONE || deviceType == MsdpDeviceType::TYPE_CAR ||
            deviceType == MsdpDeviceType::TYPE_TV || deviceType == MsdpDeviceType::TYPE_UNKNOWN);
    };

    bool IsCentralDevice() const
    {
        MsdpDeviceType deviceType = static_cast<MsdpDeviceType>(type_);
        return (deviceType == MsdpDeviceType::TYPE_TV || deviceType == MsdpDeviceType::TYPE_CAR);
    };

    void clear()
    {
        deviceId_.clear();
        type_ = 0;
        networkId_.clear();
        deviceName_.clear();
    }

    /**
    * @brief read this Sequenceable object from a Parcel.
    *
    * @param inParcel Indicates the Parcel object into which the Sequenceable object has been marshaled.
    * @return Returns true if read successed; returns false otherwise.
    */
    bool ReadFromParcel(Parcel &parcel)
    {
        deviceId_ = Str16ToStr8(parcel.ReadString16());
        deviceName_ = Str16ToStr8(parcel.ReadString16());
        networkId_ = Str16ToStr8(parcel.ReadString16());
        type_ = parcel.ReadUint32();
        return true;
    }

    /**
    * @brief Unmarshals this Sequenceable object from a Parcel.
    *
    * @param inParcel Indicates the Parcel object into which the Sequenceable object has been marshaled.
    */
    static DeviceInfo *Unmarshalling(Parcel &parcel)
    {
        DeviceInfo *deviceInfo = new (std::nothrow) DeviceInfo();
        if (deviceInfo == nullptr) {
            return nullptr;
        }
        if (deviceInfo && !deviceInfo->ReadFromParcel(parcel)) {
            delete deviceInfo;
            deviceInfo = nullptr;
        }
        return deviceInfo;
    }

    virtual bool Marshalling(Parcel &parcel) const override
    {
        return (parcel.WriteString16(Str8ToStr16(deviceId_)) &&
        parcel.WriteString16(Str8ToStr16(deviceName_)) &&
        parcel.WriteString16(Str8ToStr16(networkId_)) && parcel.WriteInt32(type_));
    };
    std::string deviceId_;
    uint32_t type_ { 0 };
    std::string networkId_;
    std::string deviceName_;
};
} // namespace UserStatusAwareness
} // namespace Msdp
} // namespace OHOS
#endif // DEVICE_INFO_H