/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef NFC_TAG_TOKENID_KIT_H
#define NFC_TAG_TOKENID_KIT_H

#include <cstdint>

namespace OHOS {
namespace Security {
namespace AccessToken {
class TokenIdKit {
public:
    static bool IsSystemAppByFullTokenID(uint64_t tokenId)
    {
        return isSystemApp_;
    }

    static bool isSystemApp_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // NFC_TAG_TOKENID_KIT_H