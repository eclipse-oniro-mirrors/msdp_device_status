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

#include "sequenceable_rotate_window.h"

#include "devicestatus_define.h"
#include "drag_data_packer.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

bool SequenceableRotateWindow::Marshalling(Parcel &parcel) const
{
    if (rsTransaction_ == nullptr) {
        FI_HILOGE("rsTransaction_ is nullptr");
        return false;
    }
    if (!parcel.WriteParcelable(rsTransaction_.get())) {
        FI_HILOGE("Write transaction sync id failed");
        return false;
    }
    return true;
}

SequenceableRotateWindow* SequenceableRotateWindow::Unmarshalling(Parcel &parcel)
{
    std::shared_ptr<Rosen::RSTransaction> rsTransaction(parcel.ReadParcelable<Rosen::RSTransaction>());
    if (rsTransaction == nullptr) {
        FI_HILOGE("UnMarshalling rsTransaction failed");
        return nullptr;
    }
    SequenceableRotateWindow *sequenceableRotateWindow = new (std::nothrow) SequenceableRotateWindow();
    CHKPP(sequenceableRotateWindow);
    sequenceableRotateWindow->rsTransaction_ = rsTransaction;
    return sequenceableRotateWindow;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS