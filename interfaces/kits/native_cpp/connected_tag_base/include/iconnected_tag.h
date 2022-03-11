/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#ifndef NAPI_ICONNECTED_TAG_H_
#define NAPI_ICONNECTED_TAG_H_

#include "iremote_object.h"
#include "error_code.h"
#include "iconnected_tag_callback.h"

namespace OHOS {
namespace ConnectedTag {
class IConnectedTag {
public:
    virtual ~IConnectedTag() = default;

    virtual ErrCode Init() = 0;

    virtual ErrCode Uninit() = 0;

    virtual ErrCode ReadNdefTag(std::string &response) = 0;

    virtual ErrCode WriteNdefTag(std::string data) = 0;

    virtual ErrCode RegListener(const sptr<IConnectedTagCallBack> &callback) = 0;

    virtual ErrCode UnregListener(const sptr<IConnectedTagCallBack> &callback) = 0;
};
}  // namespace ConnectedTag
}  // namespace OHOS
#endif /* NAPI_ICONNECTED_TAG_H_ */
