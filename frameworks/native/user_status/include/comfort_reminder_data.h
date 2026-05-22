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

#ifndef COMFORT_REMINDER_DATA_H
#define COMFORT_REMINDER_DATA_H

#include <functional>
#include <map>
#include <vector>

#include "user_status_data.h"

namespace OHOS {
namespace Msdp {
namespace UserStatusAwareness {
class ComfortReminderData : public UserStatusData {
public:
    ComfortReminderData();
    ~ComfortReminderData();

    int32_t GetFusionReminderData() const;
    void SetFusionReminderData(const int32_t fusionReminderData);

    int32_t GetSwingReminderData() const;
    void SetSwingReminderData(const int32_t swingReminderData);

    int32_t GetEventType() const;
    void SetEventType(const int32_t eventType);

    std::string Dump() override;
    std::shared_ptr<UserStatusData> Unmarshalling(Parcel &parcel) override;

    bool Marshalling(Parcel &parcel) const override;

protected:
    bool ReadFromParcel(Parcel &parcel) override;

private:
    bool MarshallComfortReminderData(Parcel &parcel) const;

    int32_t fusionReminderData_ { -1 };
    int32_t swingReminderData_ { -1 };
    int32_t eventType_ { -1 };
};
} // namespace UserStatusAwareness
} // namespace Msdp
} // namespace OHOS
#endif // COMFORT_REMINDER_DATA_H