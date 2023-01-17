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
#ifndef DRAG_MANAGER_IMPL_H
#define DRAG_MANAGER_IMPL_H

#include <string>

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class DragManagerImpl  {
public:
    DragManagerImpl() = default;
    ~DragManagerImpl() = default;
    int32_t UpdateDragStyle(int32_t style);
    int32_t UpdateDragMessage(const std::u16string &message);
    int32_t GetDragTargetPid();
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DRAG_MANAGER_IMPL_H
